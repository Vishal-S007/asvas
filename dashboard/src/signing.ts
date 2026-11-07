// PO-04: per-approver Ed25519 signatures. The private key is generated in the browser as a non-extractable
// WebCrypto key and kept in IndexedDB; only the public key is sent to the server. This is software-key signing
// (protected by the browser profile), not WebAuthn with a hardware authenticator.
import { api } from "./api";

const DB = "asvas-approver-keys", STORE = "keys";
interface Stored { keyId: string; privateKey: CryptoKey }

function idb<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const req = fn(open.result.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    };
  });
}

const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));

export function decisionMessage(approvalId: string, decision: string, bindingHash: string, expiresUnix: number) {
  return `asvas-approval-v1|${approvalId}|${decision}|${bindingHash}|${expiresUnix}`;
}

async function ensureKey(userId: string): Promise<Stored> {
  const active = await api<{ id: string; revoked_at: string | null }[]>("/approver-keys");
  const stored = await idb<Stored | undefined>("readonly", (s) => s.get(userId));
  if (stored && active.some((k) => k.id === stored.keyId && !k.revoked_at)) return stored;
  let pair: CryptoKeyPair;
  try {
    pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
  } catch {
    throw new Error("This browser does not support Ed25519 signing (WebCrypto); approvals cannot be signed here.");
  }
  const pub = b64(await crypto.subtle.exportKey("raw", pair.publicKey));
  const reg = await api<{ id: string }>("/approver-keys", { method: "POST", body: { public_key: pub, label: navigator.userAgent.slice(0, 100) } });
  const rec = { keyId: reg.id, privateKey: pair.privateKey };
  await idb("readwrite", (s) => s.put(rec, userId));
  return rec;
}

export async function signDecision(userId: string, approvalId: string, decision: string, bindingHash: string, expiresUnix: number) {
  const k = await ensureKey(userId);
  const msg = new TextEncoder().encode(decisionMessage(approvalId, decision, bindingHash, expiresUnix));
  return { key_id: k.keyId, signature: b64(await crypto.subtle.sign({ name: "Ed25519" }, k.privateKey, msg)) };
}
