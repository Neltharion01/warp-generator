// ===== Настройки =====
const MOCK = false; // true: вместо запросов к API используется тестовый ответ
const API = "https://deathwing.dedyn.io/v0a2158";
const SUB = "https://deathwing.dedyn.io/warp/subs/";
const MOCK_RES = {id:"af4e1e54-b864-4e21-bb51-b65df662487a",token:"mock",config:{client_id:"jKF4",peers:[{public_key:"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",endpoint:{host:"engage.cloudflareclient.com:2408"}}],interface:{addresses:{v4:"172.16.0.2",v6:"2606:4700:110:84c6:92ec:782c:3aee:5127"}}}};

// ===== WARP =====
const b64 = bytes => btoa(String.fromCharCode(...bytes));
const unb64 = s => [...atob(s)].map(c=>c.charCodeAt(0));
const b64url = bytes => b64(bytes).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const unb64url = s => unb64(s.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(s.length/4)*4,"="));
const validHost = h => /^[A-Za-z0-9._-]{1,253}$/.test(h); // так же проверяет сервер подписок
async function genKeys(){
  if(MOCK) return {priv:"0PYwBaNdBfp3HyAF+uca2icr++gFJu4+cH3qxytFg2k=",pub:""};
  try{
    const sc = crypto.subtle;
    const kp = await sc.generateKey({name:"X25519"},true,["deriveBits"]);
    const priv = new Uint8Array(await sc.exportKey("pkcs8",kp.privateKey)).slice(-32);
    const pub = new Uint8Array(await sc.exportKey("raw",kp.publicKey));
    return {priv:b64(priv),pub:b64(pub)};
  }catch(e){
    // нет X25519 в WebCrypto: чистый JS
    const sk = crypto.getRandomValues(new Uint8Array(32));
    sk[0] &= 248; sk[31] = (sk[31] & 127) | 64;
    return {priv:b64(sk),pub:b64(X25519.getPublic(sk))};
  }
}
async function register(pub){
  if(MOCK) return MOCK_RES;
  const r = await fetch(`${API}/reg`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({key:pub,tos:new Date().toISOString()})});
  if(!r.ok) throw new Error("reg: HTTP "+r.status);
  const reg = await r.json();
  const p = await fetch(`${API}/reg/${reg.id}`,{method:"PATCH",headers:{"Content-Type":"application/json","Authorization":"Bearer "+reg.token},body:JSON.stringify({warp_enabled:true})});
  if(!p.ok) throw new Error("enable: HTTP "+p.status);
  return p.json();
}

// ===== Masque =====
const API_MASQUE = "https://deathwing.dedyn.io/v0a4471"; // версия API как в usque
const MOCK_MASQUE_RES = {config:{interface:{addresses:{v4:"172.16.0.2",v6:"2606:4700:110:82f9:ad40:70ab:9eed:f19f"}}}};

// SubjectPublicKeyInfo для P-256: этот префикс + 04 || X || Y
const SPKI_P256 = [0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00];
async function genMasqueKeys(){
  try{
    const sc = crypto.subtle;
    const kp = await sc.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
    const spki = new Uint8Array(await sc.exportKey("spki",kp.publicKey));
    const scalar = unb64url((await sc.exportKey("jwk",kp.privateKey)).d);
    if(scalar.length!==32) throw new Error("неожиданный формат ключа");
    return {scalar,spki};
  }catch(e){
    // нет crypto.subtle (страница по HTTP) или P-256 не поддерживается: чистый JS (noble-curves)
    const {secretKey,publicKey} = P256.keygen();
    return {scalar:[...secretKey],spki:new Uint8Array([...SPKI_P256,...publicKey])};
  }
}
async function registerMasque(spki){
  if(MOCK) return MOCK_MASQUE_RES;
  // Регистрация обычная, ключ первого шага одноразовый: ключ masque заменяет его сразу
  const r = await fetch(`${API_MASQUE}/reg`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({key:b64(crypto.getRandomValues(new Uint8Array(32))),tos:new Date().toISOString()})});
  if(!r.ok) throw new Error("reg: HTTP "+r.status);
  const reg = await r.json();
  const p = await fetch(`${API_MASQUE}/reg/${reg.id}`,{method:"PATCH",headers:{"Content-Type":"application/json","Authorization":"Bearer "+reg.token},body:JSON.stringify({key:b64(spki),key_type:"secp256r1",tunnel_type:"masque"})});
  if(!p.ok) throw new Error("enroll: HTTP "+p.status);
  return p.json();
}

// ===== Общее =====
let S = null, M = null; // S - wireguard, M - masque, оба создаются одной кнопкой
const $ = id => document.getElementById(id);
function download(name,text,type){
  const a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob([text],{type}));
  a.download=name; document.body.appendChild(a); a.click(); a.remove();
}
function save(name,text,type){
  download(name,text,type);
  $("bAgain").hidden = false;
}

// ===== UI =====
function msg(t,err,id="msg") {
    $(id).hidden=t.length==0;
    $(id).textContent=t;
    $(id).className=err?"e":"";
}
const acts=["bJson","bSub"];
function setActive(on){ acts.forEach(i=>$(i).disabled=!on); }

async function genWireguard(sni){
  const keys = await genKeys();
  const res = await register(keys.pub);
  const c = res.config;
  return {priv:keys.priv,v6:c.interface.addresses.v6,reserved:[...atob(c.client_id)].map(ch=>ch.charCodeAt(0)),sni};
}
async function genMasque(sni){
  const keys = await genMasqueKeys();
  const res = await registerMasque(keys.spki);
  return {scalar:keys.scalar,v6:res.config.interface.addresses.v6,sni};
}

$("gen").onclick = async () => {
  $("gen").disabled = true; msg("Генерируем…");
  try{
    const sni = $("sni").value.trim() || $("sni").placeholder;
    const msni = $("mSni").value.trim() || $("mSni").placeholder;
    if(!validHost(sni) || !validHost(msni)) throw new Error("некорректный SNI");
    // Два независимых аккаунта WARP. S и M меняются только если удались оба
    [S, M] = await Promise.all([genWireguard(sni), genMasque(msni)]);
    setActive(true); msg("");
  }catch(e){
    $("gen").disabled = false;
    msg("Ошибка: "+(e.message||e)+(e.name==="NotSupportedError"?". Браузер не поддерживает X25519, обновите его.":""),true);
  }
};
function ipv6Bytes(a){
  const [h,t]=a.split("::");
  const hp=h?h.split(":"):[], tp=t?t.split(":"):[];
  const parts=a.includes("::") ? [...hp,...Array(8-hp.length-tp.length).fill("0"),...tp] : hp;
  const out=[]; for(const x of parts){ const v=parseInt(x||"0",16); out.push(v>>8,v&255); }
  if(out.length!==16) throw new Error("bad IPv6: "+a);
  return out;
}
// wireguard_secret = client_id[3] + privateKey[32] + ipv6[16] (51 байт, 68 символов)
// masque_secret = privateKey[32] (сырой скаляр) + ipv6[16] (48 байт, 64 символа)
const wgSecret = a => b64url([...a.reserved, ...unb64(a.priv), ...ipv6Bytes(a.v6)]);
const masqueSecret = a => b64url([...a.scalar, ...ipv6Bytes(a.v6)]);
function subLink(format){
  const w = wgSecret(S), m = masqueSecret(M);
  const q = new URLSearchParams({sni:S.sni,msni:M.sni});
  if(format) q.set("format",format);
  return `${SUB}${w}/${m}?${q}`;
}
$("bJson").onclick = async () => {
  $("bJson").disabled = true;
  try{
    // xray json собирает сервер подписок, format=json просит именно его
    const r = await fetch(subLink("json"));
    if(!r.ok) throw new Error("подписка: HTTP "+r.status);
    save("WARP.json",JSON.stringify(await r.json(),null,2),"application/json");
    msg("");
  }catch(e){ msg("Ошибка: "+(e.message||e),true); }
  $("bJson").disabled = false;
};
$("bSub").onclick = async () => {
  const l = subLink(), ic = $("ic");
  try{
    await navigator.clipboard.writeText(l);
    ic.setAttribute("href", "static/symbols.svg#check");
    setTimeout(function() {
        ic.setAttribute("href", "static/symbols.svg#link2");
    }, 2000);
  }catch(e){ prompt(e.toString() + "Скопируйте ссылку:", l); }
  $("bAgain").hidden = false;
};

// Отдельный генератор AmneziaWG: создаёт только wireguard аккаунт и сразу скачивает conf.
// S и M, а значит и остальные кнопки, не затрагиваются
// Статус пишется под самой кнопкой AmneziaWG (msgAwg), а не в общую строку под первой кнопкой
const msgAwg = (t,err) => msg(t,err,"msgAwg");
$("bAwg").onclick = async () => {
  $("bAwg").disabled = true; msgAwg("Генерируем…");
  try{
    const sni = $("sni").value.trim() || $("sni").placeholder;
    if(!validHost(sni)) throw new Error("некорректный SNI");
    const a = await genWireguard(sni);
    // masque части нет ("_"), conf собирает сервер подписок
    const r = await fetch(`${SUB}${wgSecret(a)}/_?${new URLSearchParams({sni,format:"amneziawg"})}`);
    if(!r.ok) throw new Error("подписка: HTTP "+r.status);
    // не text/plain: по нему Chrome дописывает .txt, и файл сохраняется как WARP.conf.txt
    download("WARP.conf",await r.text(),"application/octet-stream");
    msgAwg("");
  }catch(e){ msgAwg("Ошибка: "+(e.message||e),true); }
  $("bAwg").disabled = false;
};

$("bAgain").onclick = () => {
    $("bAgain").hidden = true;
    $("gen").disabled = false;
    setActive(false);
};
