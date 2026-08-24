// Public code, encrypted financial payload. Password is never stored here.
// Trusted-device mode keeps the password encrypted under a non-exportable
// AES key held in this browser's IndexedDB. It expires after 30 days.
const PF_REMEMBER_KEY='paskal-finance.unlock.v1';
const PF_REMEMBER_MS=30*24*60*60*1000;
const PF_DB_NAME='paskal-finance-device-vault';
const PF_STORE_NAME='keys';

function pfOpenVault(){
  return new Promise((resolve,reject)=>{
    const req=indexedDB.open(PF_DB_NAME,1);
    req.onupgradeneeded=()=>{
      if(!req.result.objectStoreNames.contains(PF_STORE_NAME)) req.result.createObjectStore(PF_STORE_NAME);
    };
    req.onsuccess=()=>resolve(req.result);
    req.onerror=()=>reject(req.error);
  });
}

async function pfDeviceKey(create=true){
  const db=await pfOpenVault();
  const current=await new Promise((resolve,reject)=>{
    const req=db.transaction(PF_STORE_NAME).objectStore(PF_STORE_NAME).get('unlock-key');
    req.onsuccess=()=>resolve(req.result); req.onerror=()=>reject(req.error);
  });
  if(current||!create){db.close();return current;}
  // extractable=false: JavaScript can use this key, but cannot export its bytes.
  const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  await new Promise((resolve,reject)=>{
    const req=db.transaction(PF_STORE_NAME,'readwrite').objectStore(PF_STORE_NAME).put(key,'unlock-key');
    req.onsuccess=resolve; req.onerror=()=>reject(req.error);
  });
  db.close(); return key;
}

function pfBytesToB64(bytes){return btoa(String.fromCharCode(...new Uint8Array(bytes)));}
function pfB64ToBytes(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}

async function pfRememberPassword(password){
  const key=await pfDeviceKey(true);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(password));
  localStorage.setItem(PF_REMEMBER_KEY,JSON.stringify({iv:pfBytesToB64(iv),ct:pfBytesToB64(ct),expiresAt:Date.now()+PF_REMEMBER_MS}));
}

function pfForgetDevice(){
  try{localStorage.removeItem(PF_REMEMBER_KEY);}catch(e){}
  try{sessionStorage.removeItem('pf-pass');}catch(e){}
}

async function pfRecallPassword(){
  let saved;
  try{saved=JSON.parse(localStorage.getItem(PF_REMEMBER_KEY)||'null');}catch(e){saved=null;}
  if(!saved?.iv||!saved?.ct||!saved?.expiresAt) return '';
  if(saved.expiresAt<=Date.now()){pfForgetDevice();return '';}
  try{
    const key=await pfDeviceKey(false);
    if(!key) throw new Error('Missing device key');
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:pfB64ToBytes(saved.iv)},key,pfB64ToBytes(saved.ct));
    return new TextDecoder().decode(plain);
  }catch(e){pfForgetDevice();return '';}
}

async function unlockData(url) {
  if(new URLSearchParams(location.search).has('forget')) pfForgetDevice();
  const box=document.createElement('div'); box.id='lockscreen';
  box.innerHTML=`<div class="lockcard"><div class="lockicon">🔐</div><h2>Paskal Finance</h2><p>Encrypted dashboard. Enter the private passphrase.</p><form id="unlock-form"><input class="autofill-user" name="username" value="paskal-finance" autocomplete="username" tabindex="-1"><input id="pw" name="password" type="password" autocomplete="current-password" autocapitalize="none" spellcheck="false" placeholder="Passphrase"><label class="remember"><input id="remember" type="checkbox" checked>Remember this device for 30 days</label><button id="unlock" type="submit">Unlock</button></form><div id="err"></div></div>`;
  document.body.prepend(box);
  const style=document.createElement('style');
  style.textContent=`#lockscreen{position:fixed;z-index:9999;inset:0;background:#0d1117;display:flex;align-items:center;justify-content:center;font-family:-apple-system,sans-serif}.lockcard{width:min(90vw,390px);background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:14px;padding:30px;text-align:center}.lockicon{font-size:2.4rem;margin-bottom:10px}.lockcard h2{margin:5px}.lockcard p{color:#8b949e;font-size:.9rem;margin:10px 0 20px}.lockcard input[type=password]{width:100%;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:13px;font-size:16px;margin-bottom:12px}.lockcard button{width:100%;background:#238636;color:white;border:0;border-radius:8px;padding:13px;font-size:16px;font-weight:600;cursor:pointer}.remember{display:flex;align-items:center;gap:9px;color:#8b949e;font-size:.8rem;text-align:left;margin:0 2px 14px;cursor:pointer}.remember input{width:16px;height:16px;accent-color:#238636}.autofill-user{position:absolute;left:-9999px;width:1px;height:1px;opacity:0;pointer-events:none}#err{color:#f85149;font-size:.85rem;margin-top:10px;min-height:18px}`;
  document.head.appendChild(style);

  const payload=await fetch(url).then(r=>{if(!r.ok)throw new Error('Encrypted data unavailable');return r.json();});
  const dec=new TextDecoder(),enc=new TextEncoder();
  async function decrypt(password){
    const material=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);
    const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:pfB64ToBytes(payload.salt),iterations:310000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:pfB64ToBytes(payload.iv)},key,pfB64ToBytes(payload.data));
    return JSON.parse(dec.decode(plain));
  }

  return new Promise(resolve=>{
    const input=box.querySelector('#pw'),button=box.querySelector('#unlock'),err=box.querySelector('#err'),remember=box.querySelector('#remember'),form=box.querySelector('#unlock-form');
    async function go(automatic=false){
      button.disabled=true;button.textContent=automatic?'Unlocking trusted device…':'Decrypting…';err.textContent='';
      try{
        const data=await decrypt(input.value);
        sessionStorage.setItem('pf-pass',input.value);
        if(!automatic&&remember.checked){try{await pfRememberPassword(input.value);}catch(e){console.warn('Could not remember device');}}
        if(!remember.checked) pfForgetDevice();
        box.remove();resolve(data);
      }catch(e){
        if(automatic){pfForgetDevice();input.value='';remember.checked=true;err.textContent='Saved unlock expired. Enter the password again.';}
        else err.textContent='Wrong password or damaged data.';
        button.disabled=false;button.textContent='Unlock';input.focus();input.select();
      }
    }
    form.onsubmit=e=>{e.preventDefault();go(false);};
    (async()=>{
      let password=sessionStorage.getItem('pf-pass')||'';
      if(!password) password=await pfRecallPassword();
      if(password){input.value=password;remember.checked=true;await go(true);}else input.focus();
    })();
  });
}
