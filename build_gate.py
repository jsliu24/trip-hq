#!/usr/bin/env python3
"""Encrypt index.html into a password-gated static page (AES-256-GCM, PBKDF2-SHA256).
Usage: python3 build_gate.py <password> <in.html> <out.html>

Gate features:
  - "Remember this device"  -> derived key in localStorage (can be evicted by iOS)
  - #password in the URL    -> auto-unlock with no storage dependency (home-screen shortcut)
  - username + autocomplete -> iCloud Keychain / password managers offer to fill, and
                               the form self-submits when they do
  - apple-touch-icon + web-app metas so the home-screen tile looks like a real app
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
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>Spain Trip — Liu Family</title>
<link rel="apple-touch-icon" href="icon-180.png">
<link rel="icon" type="image/png" sizes="32x32" href="icon-32.png">
<link rel="icon" type="image/png" sizes="192x192" href="icon-192.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Spain Trip">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="theme-color" content="#f4f5f7" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#101318" media="(prefers-color-scheme: dark)">
<style>
  :root{--bg:#f4f5f7;--surface:#fff;--ink:#1a1d21;--ink2:#5a6572;--line:#e4e7ec;--accent:#2456c9}
  @media (prefers-color-scheme:dark){:root{--bg:#101318;--surface:#1a1f27;--ink:#eceff3;--ink2:#a6afbc;--line:#2a313b;--accent:#7da2f2}}
  body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    display:flex;min-height:100vh;align-items:center;justify-content:center;padding:20px;box-sizing:border-box}
  .box{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:24px;max-width:340px;width:100%;text-align:center}
  .box img.mark{width:64px;height:64px;border-radius:15px;display:block;margin:0 auto 10px}
  h1{font-size:19px;margin:0 0 4px}
  p{color:var(--ink2);font-size:13.5px;margin:0 0 16px}
  input{width:100%;box-sizing:border-box;font-size:17px;padding:12px 14px;border-radius:10px;
    border:1px solid var(--line);background:var(--bg);color:var(--ink);outline:none;text-align:center}
  input:focus{border-color:var(--accent)}
  input#user{font-size:14px;padding:9px 12px;color:var(--ink2);margin-bottom:8px}
  button{width:100%;margin-top:10px;font-size:16px;font-weight:600;padding:12px;border-radius:10px;border:none;
    background:var(--accent);color:#fff;cursor:pointer}
  label{display:flex;gap:7px;align-items:center;justify-content:center;font-size:13px;color:var(--ink2);margin-top:12px}
  .err{color:#c0392b;font-size:13px;min-height:18px;margin-top:10px}
</style>
</head>
<body>
<form class="box" id="f">
  <img class="mark" src="icon-192.png" alt="">
  <h1>Spain Trip Dashboard</h1>
  <p>Enter the family password</p>
  <input type="text" id="user" name="username" autocomplete="username" value="Liu family" aria-label="Account">
  <input type="password" id="pw" name="password" autocomplete="current-password" placeholder="Password" autofocus>
  <button type="submit">Unlock</button>
  <label><input type="checkbox" id="rem" checked style="width:auto"> Remember this device</label>
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
async function remember(key){
  try{
    const raw = await crypto.subtle.exportKey("raw", key);
    localStorage.setItem("trip_key", btoa(String.fromCharCode(...new Uint8Array(raw))));
  }catch(_){}
}
async function unlock(key){
  /* document.open() is a no-op while the parser is still running, which would make
     document.write() APPEND the dashboard under the still-visible password box.
     The stored-key path is fast enough to hit that race, so wait for parsing first. */
  if(document.readyState === "loading"){
    await new Promise(r => document.addEventListener("DOMContentLoaded", r, {once:true}));
  }
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:b(P.iv)}, key, b(P.ct));
  const html = new TextDecoder().decode(pt);
  document.open(); document.write(html); document.close();
}
/* 1. password in the URL fragment — survives any storage eviction.
      The fragment is never sent to the server. Used by the home-screen shortcut. */
async function tryHash(){
  const h = decodeURIComponent((location.hash || "").replace(/^#/, "")).trim();
  if(!h) return false;
  try{
    const key = await keyFromPw(h);
    await remember(key);          /* must happen before unlock(): document.write kills this context */
    await unlock(key);
    return true;
  }catch(e){ return false; }
}
/* 2. key saved by "remember this device" */
async function tryStored(){
  try{
    const raw = localStorage.getItem("trip_key");
    if(!raw) return;
    const key = await crypto.subtle.importKey("raw", b(raw), {name:"AES-GCM"}, false, ["decrypt"]);
    await unlock(key);
  }catch(e){ try{localStorage.removeItem("trip_key");}catch(_){} }
}
/* 3. typed, or filled by a password manager (then submit itself) */
const form = document.getElementById("f"), pwEl = document.getElementById("pw");
let typed = false;
pwEl.addEventListener("keydown", () => { typed = true; });
pwEl.addEventListener("input", () => {
  if(!typed && pwEl.value.length >= 4){
    if(form.requestSubmit) form.requestSubmit(); else form.dispatchEvent(new Event("submit",{cancelable:true}));
  }
});
form.addEventListener("submit", async ev => {
  ev.preventDefault();
  const err = document.getElementById("err"); err.textContent = "";
  try{
    const key = await keyFromPw(pwEl.value.trim());
    if(document.getElementById("rem").checked) await remember(key);
    await unlock(key);
  }catch(e){ err.textContent = "Wrong password — try again."; typed = true; }
});
(async function boot(){ if(await tryHash()) return; await tryStored(); })();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
