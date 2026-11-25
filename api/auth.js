import { random,hash,challenge,seal,unseal,equal,validSecret,verifyIdentity,cookies,cookie,issuer } from '../lib/security.mjs';
const FLOW='__Host-sg_flow', DEVICE='__Host-sg_device';
let jwksCache;
const blank={signedIn:false,trusted:false,fresh:false,expiresAt:null,desktop:null};
function config(env) {
  const {APP_ORIGIN:origin,TELEGRAM_CLIENT_ID:clientId,TELEGRAM_CLIENT_SECRET:secret,TELEGRAM_OWNER_ID:ownerId,FLOW_KEY:key,SUPABASE_URL:db,SUPABASE_SECRET_KEY:dbKey}=env;
  if(!origin||!clientId||!secret||!ownerId||!key||!db||!dbKey||!/^\d+$/.test(clientId)||!/^\d+$/.test(ownerId)||! /^[a-f\d]{64}$/i.test(key)||!/^sb_secret_/.test(dbKey)) throw Error('Configuration incomplete');
  if(new URL(origin).origin!==origin||!origin.startsWith('https://')||new URL(db).origin!==db||!db.startsWith('https://')) throw Error('Invalid origin');
  return {origin,clientId,secret,ownerId,key,db,dbKey,redirect:origin+'/api/callback'};
}
async function transition(c,action,token,next=null,fetcher=fetch) {
  const r=await fetcher(c.db+'/rest/v1/rpc/sg_transition',{method:'POST',headers:{apikey:c.dbKey,'Content-Type':'application/json'},body:JSON.stringify({p_owner:c.ownerId,p_action:action,p_hash:validSecret(token)?hash(token):'',p_new:next?hash(next):null}),signal:AbortSignal.timeout(10000)});
  if(!r.ok) throw Error('Database unavailable'); return r.json();
}
async function telegram(c,code,verifier,fetcher=fetch) {
  const r=await fetcher(issuer+'/token',{method:'POST',headers:{Authorization:'Basic '+Buffer.from(c.clientId+':'+c.secret).toString('base64'),'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:c.redirect,client_id:c.clientId,code_verifier:verifier}),signal:AbortSignal.timeout(10000),redirect:'error'});
  if(!r.ok) throw Error('Telegram authorization failed');
  const {id_token}=await r.json();
  async function keys(force=false){if(!force&&jwksCache?.until>Date.now())return jwksCache.data;const resp=await fetcher(issuer+'/.well-known/jwks.json',{signal:AbortSignal.timeout(10000),redirect:'error'});if(!resp.ok)throw Error('Key lookup failed');const data=await resp.json();jwksCache={data,until:Date.now()+300000};return data;}
  try{return verifyIdentity(id_token,await keys(),c);}catch{return verifyIdentity(id_token,await keys(true),c);}
}
export function createHandler({env=process.env,fetcher=fetch,dbTransition=transition,verifyTelegram=telegram}={}) {
 return async (req,res)=>{
  res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Content-Type-Options','nosniff');
  const send=(status,body)=>{res.statusCode=status;res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify(body));};
  const redirect=(to,jar=[])=>{res.statusCode=303;res.setHeader('Location',to);if(jar.length)res.setHeader('Set-Cookie',jar);res.end();};
  let c;try{c=config(env);}catch{return send(503,{error:'Shellagram is not configured yet.'});}
  const url=new URL(req.url,c.origin), action=url.pathname==='/api/callback'?'callback':url.searchParams.get('action')||'status', jar=cookies(req.headers.cookie), token=jar[DEVICE];
  if(action!=='status'&&action!=='callback'&&(req.method!=='POST'||req.headers.origin!==c.origin))return send(403,{error:'Request rejected'});
  if((action==='status'||action==='callback')&&req.method!=='GET')return send(405,{error:'Method not allowed'});
  try{
    if(action==='start'){
      const state=random(),verifier=random();const flow=seal({state,verifier,exp:Date.now()+600000},c.key);
      const u=new URL(issuer+'/auth');u.search=new URLSearchParams({client_id:c.clientId,redirect_uri:c.redirect,response_type:'code',scope:'openid profile',state,code_challenge:challenge(verifier),code_challenge_method:'S256'});
      return redirect(u.toString(),[cookie(FLOW,flow,600)]);
    }
    if(action==='callback'){
      const clear=cookie(FLOW,'',0);
      try{
        const flow=unseal(jar[FLOW],c.key),code=url.searchParams.get('code');
        if(url.searchParams.has('error')||!equal(flow.state,url.searchParams.get('state'))||!code||code.length>2048)throw Error('Invalid callback');
        if(await verifyTelegram(c,code,flow.verifier,fetcher)!==c.ownerId)throw Error('Account not allowed');
        const fresh=random();await dbTransition(c,'login',token,fresh,fetcher);
        return redirect('/?login=success',[clear,cookie(DEVICE,fresh,90*86400)]);
      }catch{return redirect('/?login=failed',[clear]);}
    }
    if(!['status','trust','logout','lock-desktop','forget-desktop','lock-all'].includes(action))return send(404,{error:'Unknown action'});
    if(!validSecret(token))return action==='status'?send(200,blank):send(401,{error:'Sign in first'});
    const result=await dbTransition(c,action,token,null,fetcher);
    if(result.error)return send(403,{error:result.error});
    if(action==='logout'&&!result.trusted)res.setHeader('Set-Cookie',cookie(DEVICE,'',0));
    if(action==='forget-desktop'&&!result.signedIn)res.setHeader('Set-Cookie',cookie(DEVICE,'',0));
    return send(200,result);
  }catch{return send(503,{error:'Authentication service temporarily unavailable.'});}
 };
}
export default createHandler();
