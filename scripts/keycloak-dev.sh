#!/usr/bin/env bash
# Local Keycloak for CP-07 (OIDC SSO + MFA). DEVELOPMENT ONLY: runs Keycloak in dev mode (embedded H2) over
# TLS 1.3 with the dev services certificate. Production needs a real Keycloak deployment with a database.
#   scripts/keycloak-dev.sh start   -> start on https://localhost:8443 (admin password in var/keycloak/, 0600)
#   scripts/keycloak-dev.sh setup   -> create realm "asvas", PKCE client, roles, TOTP-required users
#   scripts/keycloak-dev.sh stop
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
KC="$ROOT/.tools/keycloak/bin"; OUT="$ROOT/var/keycloak"; URL="https://localhost:8443"
mkdir -p "$OUT" var/logs var/run && chmod 700 "$OUT"
unset JAVA_TOOL_OPTIONS
case "${1:-}" in
start)
  [ -x "$KC/kc.sh" ] || { echo "Keycloak missing: download keycloak-26.4.2.tar.gz into .tools/keycloak (see README)"; exit 1; }
  [ -f "$OUT/admin-password" ] || (umask 077; openssl rand -hex 16 > "$OUT/admin-password")
  KC_BOOTSTRAP_ADMIN_USERNAME=kcadmin KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat "$OUT/admin-password")" \
  nohup "$KC/kc.sh" start-dev --http-host=127.0.0.1 --https-port=8443 --https-protocols=TLSv1.3 \
    --https-certificate-file="$ROOT/var/certs/services.crt" --https-certificate-key-file="$ROOT/var/certs/services.key" \
    --hostname="$URL" > var/logs/keycloak.log 2>&1 &
  echo $! > var/run/keycloak.pid
  for _ in $(seq 60); do curl -sf --cacert var/certs/ca.crt "$URL/realms/master" >/dev/null && { echo "keycloak up: $URL"; exit 0; }; sleep 3; done
  echo "keycloak did not start; see var/logs/keycloak.log"; exit 1 ;;
stop)
  [ -f var/run/keycloak.pid ] && kill "$(cat var/run/keycloak.pid)" 2>/dev/null || true; pkill -f "keycloak.*start-dev" || true ;;
setup)
  TS="$OUT/truststore.p12"
  [ -f "$TS" ] || keytool -importcert -noprompt -alias asvas-dev-ca -file var/certs/ca.crt -keystore "$TS" \
    -storetype PKCS12 -storepass changeit >/dev/null 2>&1
  export KC_OPTS="-Djavax.net.ssl.trustStore=$TS -Djavax.net.ssl.trustStorePassword=changeit"
  A="$KC/kcadm.sh"; CFG="--config $OUT/kcadm.config"
  $A config credentials $CFG --server "$URL" --realm master --user kcadmin --password "$(cat "$OUT/admin-password")" >/dev/null
  $A get realms/asvas $CFG >/dev/null 2>&1 && { echo "realm asvas exists"; } || \
    $A create realms $CFG -s realm=asvas -s enabled=true -s sslRequired=all -s registrationAllowed=false \
      -s bruteForceProtected=true -s accessTokenLifespan=600 -s 'otpPolicyAlgorithm=HmacSHA1' -s otpPolicyDigits=6 >/dev/null
  # TOTP is a required action for every user: first sign-in enrolls an authenticator; afterwards the default
  # browser flow asks for the code whenever the user has OTP configured (i.e. always).
  $A update authentication/required-actions/CONFIGURE_TOTP -r asvas $CFG -s enabled=true -s defaultAction=true
  for r in viewer auditor operator approver admin; do
    $A create roles -r asvas $CFG -s name="asvas-$r" >/dev/null 2>&1 || true
  done
  if ! $A get clients -r asvas $CFG -q clientId=asvas-dashboard --fields id | grep -q '"id"'; then
    $A create clients -r asvas $CFG -f - >/dev/null <<'J'
{"clientId":"asvas-dashboard","publicClient":true,"standardFlowEnabled":true,"directAccessGrantsEnabled":false,
 "implicitFlowEnabled":false,"redirectUris":["http://localhost:5173/auth/callback","http://127.0.0.1:5173/auth/callback"],
 "webOrigins":["http://localhost:5173","http://127.0.0.1:5173"],"attributes":{"pkce.code.challenge.method":"S256",
 "post.logout.redirect.uris":"http://localhost:5173/*"},
 "protocolMappers":[
  {"name":"audience","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper",
   "config":{"included.custom.audience":"asvas-api","access.token.claim":"true","id.token.claim":"false"}},
  {"name":"amr","protocol":"openid-connect","protocolMapper":"oidc-amr-mapper",
   "config":{"access.token.claim":"true","id.token.claim":"true","introspection.token.claim":"true"}}]}
J
  fi
  # Keep redirect URIs/origins current (dev server :5173 and production-build preview :4173)
  CID=$($A get clients -r asvas $CFG -q clientId=asvas-dashboard --fields id | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
  $A update "clients/$CID" -r asvas $CFG \
    -s 'redirectUris=["http://localhost:5173/auth/callback","http://127.0.0.1:5173/auth/callback","http://127.0.0.1:4173/auth/callback"]' \
    -s 'webOrigins=["http://localhost:5173","http://127.0.0.1:5173","http://127.0.0.1:4173"]'
  # Reference values so the AMR claim reports which factors were used ("pwd", "otp"); the API requires "otp".
  FLOW=browser
  for ex in $($A get "authentication/flows/$FLOW/executions" -r asvas $CFG | python3 -c '
import json,sys
for e in json.load(sys.stdin):
    if e.get("providerId") in ("auth-username-password-form","auth-otp-form"): print(e["id"]+":"+e["providerId"])'); do
    id=${ex%%:*}; prov=${ex#*:}; ref=$([ "$prov" = auth-otp-form ] && echo otp || echo pwd)
    $A create "authentication/executions/$id/config" -r asvas $CFG -s alias="amr-$ref-$id" \
      -s "config.\"default.reference.value\"=$ref" -s "config.\"default.reference.maxAge\"=36000" >/dev/null 2>&1 || true
  done
  # Development users mirror the seeded ASVAS users; random passwords are written to var/keycloak/dev-users.json (0600).
  python3 - "$OUT/dev-users.json" <<'P'
import json, os, secrets, sys
p = sys.argv[1]
users = json.load(open(p)) if os.path.exists(p) else {}
for email, role in [("admin@acme.test","admin"),("approver@acme.test","approver"),("operator@acme.test","operator"),
                    ("viewer@acme.test","viewer"),("auditor@acme.test","auditor"),("operator@globex.test","operator")]:
    users.setdefault(email, {"role": role, "password": secrets.token_urlsafe(18)})
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f: json.dump(users, f, indent=1)
P
  python3 -c 'import json,sys; [print(e, u["role"], u["password"]) for e,u in json.load(open(sys.argv[1])).items()]' "$OUT/dev-users.json" |
  while read -r email role pw; do
    if ! $A get users -r asvas $CFG -q email="$email" -q exact=true --fields id | grep -q '"id"'; then
      $A create users -r asvas $CFG -s username="$email" -s email="$email" -s emailVerified=true -s enabled=true \
        -s 'requiredActions=["CONFIGURE_TOTP"]' >/dev/null
      $A set-password -r asvas $CFG --username "$email" --new-password "$pw"
      $A add-roles -r asvas $CFG --uusername "$email" --rolename "asvas-$role"
    fi
    uid=$($A get users -r asvas $CFG -q email="$email" -q exact=true --fields id | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
    # complete profile (otherwise Keycloak's VERIFY_PROFILE action interrupts the first sign-in)
    $A update "users/$uid" -r asvas $CFG -s firstName="Dev" -s lastName="User" -s email="$email" -s emailVerified=true
  done
  echo "realm asvas ready: issuer $URL/realms/asvas, client asvas-dashboard; dev user passwords in $OUT/dev-users.json" ;;
*) echo "usage: $0 start|stop|setup"; exit 2 ;;
esac
