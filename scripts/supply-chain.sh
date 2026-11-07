#!/usr/bin/env bash
# NF-04: generate CycloneDX SBOMs for all three components and scan dependencies for known vulnerabilities.
# Exits non-zero if a scanner reports a known vulnerability (Go: only vulnerabilities reachable from our code,
# as determined by govulncheck's call-graph analysis; Python and npm: any known vulnerability in runtime deps).
# Tools (pinned): govulncheck v1.1.4, cyclonedx-gomod v1.9.0, pip-audit 2.9.0, cyclonedx-bom 7.1.0, npm >= 10.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/var/sbom}"
mkdir -p "$OUT"
fail=0

echo "== Python (control plane)"
(cd "$ROOT/control-plane" && uv export --frozen --no-dev --no-hashes --no-emit-project -o "$OUT/control-plane.requirements.txt" >/dev/null)
cyclonedx-py requirements "$OUT/control-plane.requirements.txt" --of JSON -o "$OUT/control-plane.cdx.json"
pip-audit -r "$OUT/control-plane.requirements.txt" --disable-pip --no-deps --progress-spinner off \
  -f json -o "$OUT/control-plane.audit.json" || fail=1
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); v=[(x['name'],x['version'],y['id']) for x in d['dependencies'] for y in x.get('vulns',[])]; print(f'  {len(d[\"dependencies\"])} packages, {len(v)} known vulnerabilities'); [print('  ', *t) for t in v]" "$OUT/control-plane.audit.json"

echo "== Go (execution plane)"
(cd "$ROOT/execution-plane" && cyclonedx-gomod mod -json -output "$OUT/execution-plane.cdx.json" . 2>/dev/null)
(cd "$ROOT/execution-plane" && govulncheck -format json ./... > "$OUT/execution-plane.govulncheck.json") || true
(cd "$ROOT/execution-plane" && govulncheck ./... > "$OUT/execution-plane.govulncheck.txt" 2>&1) || { fail=1; cat "$OUT/execution-plane.govulncheck.txt"; }
grep -E "Your code is affected|No vulnerabilities found" "$OUT/execution-plane.govulncheck.txt" | sed 's/^/  /' || true

echo "== npm (dashboard)"
(cd "$ROOT/dashboard" && npm sbom --sbom-format cyclonedx --omit dev > "$OUT/dashboard.cdx.json")
(cd "$ROOT/dashboard" && npm audit --omit=dev --json > "$OUT/dashboard.audit.json") || fail=1
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); m=d.get('metadata',{}).get('vulnerabilities',{}); print('  ', m)" "$OUT/dashboard.audit.json"

for f in "$OUT"/*.cdx.json; do
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['bomFormat']=='CycloneDX'; print(f'  SBOM {sys.argv[1].rsplit(\"/\",1)[1]}: CycloneDX {d[\"specVersion\"]}, {len(d.get(\"components\",[]))} components')" "$f"
done
exit $fail
