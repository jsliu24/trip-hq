#!/usr/bin/env python3
"""Encrypt index.html into a password-gated static page (AES-256-GCM, PBKDF2-SHA256).
Usage: python3 build_gate.py <password> <in.html> <out.html>
"""
import sys, os, base64, json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 310000

def main():
    password, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    plaintext = open(src, "rb").read()
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(password.encode())
    ct = AESGCM(key).encrypt(iv, plaintext, None)
    b64 = lambda b: base64.b64encode(b).decode()
    payload = json.dumps({"salt": b64(salt), "iv": b64(iv), "ct": b64(ct), "iter": ITER})
    gate = TEMPLATE.replace("__PAYLOAD__", payload)
    open(dst, "w").write(gate)
    print(f"wrote {dst}: {len(gate)} bytes (plaintext {len(plaintext)}, ct {len(ct)})")

TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Spain Trip — Liu Family</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>✈️</text></svg>">
<style>
  :root{--bg:#f4f5f7;--surface:#fff;--ink:#1a1d21;--ink2:#5a6572;--line:#e4e7ec;--accent:#2456c9}
  @media (prefers-color-scheme:dark){:root{--bg:#101318;--surface:#1a1f27;--ink:#eceff3;--ink2:#a6afbc;--line:#2a313b;--accent:#7da2f2}}
  body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    display:flex;min-height:100vh;align-items:center;justify-content:center;padding:20px;box-sizing:border-box}
  .box{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:28px 24px;max-width:340px;width:100%;text-align:center}
  .box .e{font-size:40px;margin-bottom:6px}
  h1{font-size:19px;margin:0 0 4px}
  p{color:var(--ink2);font-size:13.5px;margin:0 0 18px}
  input[type=password]{width:100%;box-sizing:border-box;font-size:17px;padding:12px 14px;border-radius:10px;
    border:1px solid var(--line);background:var(--bg);color:var(--ink);outline:none;text-align:center}
  input[type=password]:focus{border-color:var(--accent)}
  button{width:100%;margin-top:10px;font-size:16px;font-weight:600;padding:12px;border-radius:10px;border:none;
    background:var(--accent);color:#fff;cursor:pointer}
  label{display:flex;gap:7px;align-items:center;justify-content:center;font-size:13px;color:var(--ink2);margin-top:12px}
  .err{color:#c0392b;font-size:13px;min-height:18px;margin-top:10px}
</style>
</head>
<body>
<form class="box" id="f">
  <div class="e">🔒</div>
  <h1>Spain Trip Dashboard</h1>
  <p>Enter the family password</p>
  <input type="password" id="pw" autocomplete="current-password" placeholder="Password" autofocus>
  <button type="submit">Unlock</button>
  <label><input type="checkbox" id="rem" checked> Remember this device</label>
  <div class="err" id="err"></div>
</form>
<script>
const P = __PAYLOAD__;
const b = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function keyFromPw(pw){
  const mat = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt:b(P.salt), iterations:P.iter, hash:"SHA-256"},
    mat, {name:"AES-GCM", length:256}, true, ["decrypt"]);
}
async function unlock(key){
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:b(P.iv)}, key, b(P.ct));
  const html = new TextDecoder().decode(pt);
  document.open(); document.write(html); document.close();
}
async function tryStored(){
  try{
    const raw = localStorage.getItem("trip_key");
    if(!raw) return;
    const key = await crypto.subtle.importKey("raw", b(raw), {name:"AES-GCM"}, false, ["decrypt"]);
    await unlock(key);
  }catch(e){ try{localStorage.removeItem("trip_key");}catch(_){} }
}
document.getElementById("f").addEventListener("submit", async ev => {
  ev.preventDefault();
  const err = document.getElementById("err"); err.textContent = "";
  try{
    const key = await keyFromPw(document.getElementById("pw").value.trim());
    if(document.getElementById("rem").checked){
      try{
        const raw = await crypto.subtle.exportKey("raw", key);
        localStorage.setItem("trip_key", btoa(String.fromCharCode(...new Uint8Array(raw))));
      }catch(_){}
    }
    await unlock(key);
  }catch(e){ err.textContent = "Wrong password — try again."; }
});
tryStored();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
