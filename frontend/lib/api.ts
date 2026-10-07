const API=process.env.NEXT_PUBLIC_API_URL||'http://localhost:8000/api';
export async function api(path:string,init?:RequestInit){const r=await fetch(API+path,{...init,headers:{'Content-Type':'application/json',...(init?.headers||{})}}); if(!r.ok) throw new Error(await r.text()); return r.json()}
export {API};
