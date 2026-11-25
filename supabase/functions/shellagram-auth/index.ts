import { random,hash,challenge,seal,unseal,equal,validSecret,verifyIdentity,issuer } from './security.mjs';
import { Buffer } from 'node:buffer';
const ORIGIN='https://marcusdhaynes.github.io', REDIRECT=ORIGIN+'/Shellagram/';
const cors={'Access-Control-Allow-Origin':ORIGIN,'Access-Control-Allow-Methods':'POST, OPTIONS','Access-Control-Allow-Headers':'content-type','Vary':'Origin','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{...cors,'Content-Type':'application/json'}});
const blank={signedIn:false,trusted:false,fresh:false,expiresAt:null,desktop:null};
let keysCache;
function config(){const clientId=Deno.env.get('SHELLAGRAM_TELEGRAM_CLIENT_ID'),secret=Deno.env.get('SHELLAGRAM_TELEGRAM_CLIENT_SECRET'),ownerId=Deno.env.get('SHELLAGRAM_TELEGRAM_OWNER_ID'),db=Deno.env.get('SUPABASE_URL'),key=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');if(!/^\d+$/.test(clientId||'')||!secret||!/^\d+$/.test(ownerId||'')||!db||!key)return null;return {clientId,secret,ownerId,db,key,flowKey:hash('shellagram-flow-v1:'+secret)};}
async function transition(c,action,token,next=null){const r=await fetch(c.db+'/rest/v1/rpc/shellagram_transition',{method:'POST',headers:{apikey:c.key,Authorization:'Bearer '+c.key,'Content-Type':'application/json'},body:JSON.stringify({p_owner:c.ownerId,p_action:action,p_hash:validSecret(token)?hash(token):'',p_new:next?hash(next):null}),signal:AbortSignal.timeout(10000),redirect:'error'});if(!r.ok)throw Error('Database unavailable');return r.json();}
async function verifyTelegram(c,code,verifier){const r=await fetch(issuer+'/token',{method:'POST',headers:{Authorization:'Basic '+Buffer.from(c.clientId+':'+c.secret).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:REDIRECT,client_id:c.clientId,code_verifier:verifier}),signal:AbortSignal.timeout(10000),redirect:'error'});if(!r.ok)throw Error('Telegram authorization failed');const {id_token}=await r.json();async function keys(force=false){if(!force&&keysCache?.until>Date.now())return keysCache.data;const rr=await fetch(issuer+'/.well-known/jwks.json',{signal:AbortSignal.timeout(10000),redirect:'error'});if(!rr.ok)throw Error('Keys unavailable');const data=await rr.json();keysCache={data,until:Date.now()+300000};return data;}try{return verifyIdentity(id_token,await keys(),c);}catch{return verifyIdentity(id_token,await keys(true),c);}}
Deno.serve(async req=>{
 if(req.headers.get('origin')!==ORIGIN)return reply({error:'Origin rejected'},403);
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers:cors});
 if(req.method!=='POST')return reply({error:'Method not allowed'},405);
 if(!req.headers.get('content-type')?.startsWith('application/json'))return reply({error:'JSON required'},415);
 const c=config();if(!c)return reply({error:'Shellagram is awaiting Telegram configuration.'},503);
 let b;try{const raw=await req.text();if(raw.length>8192)return reply({error:'Request too large'},413);b=JSON.parse(raw);if(!b||typeof b!=='object'||Array.isArray(b))throw Error();}catch{return reply({error:'Invalid request'},400);}
 const {action,token}=b;
 try{
 if(action==='start'){const state=random(),verifier=random(),flow=seal({state,verifier,exp:Date.now()+600000},c.flowKey),u=new URL(issuer+'/auth');u.search=new URLSearchParams({client_id:c.clientId,redirect_uri:REDIRECT,response_type:'code',scope:'openid profile',state,code_challenge:challenge(verifier),code_challenge_method:'S256'});return reply({url:u.toString(),flow,state});}
 if(action==='finish'){let f;try{f=unseal(b.flow,c.flowKey);if(!equal(f.state,b.state)||typeof b.code!=='string'||!b.code||b.code.length>2048)throw Error();if(await verifyTelegram(c,b.code,f.verifier)!==c.ownerId)throw Error();}catch{return reply({error:'Telegram login rejected or expired.'},401);}const fresh=random(),s=await transition(c,'login',token,fresh);return reply({...s,token:fresh});}
 if(!['status','trust','logout','lock-desktop','forget-desktop','lock-all'].includes(action))return reply({error:'Unknown action'},404);
 if(!validSecret(token))return action==='status'?reply(blank):reply({error:'Sign in first'},401);
 const s=await transition(c,action,token);return reply(s,s.error?403:200);
 }catch{return reply({error:'Authentication service temporarily unavailable.'},503);}
});
