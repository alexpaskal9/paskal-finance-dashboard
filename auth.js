// Public code, encrypted financial payload. Password is never stored here.
async function unlockData(url) {
  const box = document.createElement('div');
  box.id = 'lockscreen';
  box.innerHTML = `<div class="lockcard"><div class="lockicon">🔐</div><h2>Paskal Finance</h2><p>Encrypted dashboard. Enter the private passphrase.</p><input id="pw" type="password" autocomplete="current-password" placeholder="Passphrase"><button id="unlock">Unlock</button><div id="err"></div></div>`;
  document.body.prepend(box);
  const style = document.createElement('style');
  style.textContent = `#lockscreen{position:fixed;z-index:9999;inset:0;background:#0d1117;display:flex;align-items:center;justify-content:center;font-family:-apple-system,sans-serif}.lockcard{width:min(90vw,390px);background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:14px;padding:30px;text-align:center}.lockicon{font-size:2.4rem;margin-bottom:10px}.lockcard h2{margin:5px}.lockcard p{color:#8b949e;font-size:.9rem;margin:10px 0 20px}.lockcard input{width:100%;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:13px;font-size:16px;margin-bottom:10px}.lockcard button{width:100%;background:#238636;color:white;border:0;border-radius:8px;padding:13px;font-size:16px;font-weight:600;cursor:pointer}#err{color:#f85149;font-size:.85rem;margin-top:10px}`;
  document.head.appendChild(style);

  const payload = await fetch(url).then(r => { if (!r.ok) throw new Error('Encrypted data unavailable'); return r.json(); });
  const dec = new TextDecoder(), enc = new TextEncoder();
  function b64(s){ return Uint8Array.from(atob(s), c=>c.charCodeAt(0)); }
  async function decrypt(password) {
    const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({name:'PBKDF2',salt:b64(payload.salt),iterations:310000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
    const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(payload.iv)},key,b64(payload.data));
    return JSON.parse(dec.decode(plain));
  }
  return new Promise(resolve => {
    const input=box.querySelector('#pw'), button=box.querySelector('#unlock'), err=box.querySelector('#err');
    async function go(){
      button.disabled=true; button.textContent='Decrypting…'; err.textContent='';
      try { const data=await decrypt(input.value); sessionStorage.setItem('pf-pass',input.value); box.remove(); resolve(data); }
      catch(e){ err.textContent='Wrong password or damaged data.'; button.disabled=false; button.textContent='Unlock'; input.select(); }
    }
    button.onclick=go; input.onkeydown=e=>{if(e.key==='Enter')go()};
    input.value=sessionStorage.getItem('pf-pass')||''; input.focus(); if(input.value) go();
  });
}
