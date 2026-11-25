import { Buffer } from 'node:buffer';
import { randomBytes, createHash, createCipheriv, createDecipheriv, timingSafeEqual, createPublicKey, verify } from 'node:crypto';
export const random = () => randomBytes(32).toString('base64url');
export const hash = value => createHash('sha256').update(value).digest('hex');
export const challenge = value => createHash('sha256').update(value).digest('base64url');
export const validSecret = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
export const equal = (a,b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a),Buffer.from(b));
export const issuer = 'https://oauth.telegram.org';
export function seal(data,key) {
  const iv=randomBytes(12), c=createCipheriv('aes-256-gcm',Buffer.from(key,'hex'),iv);
  return Buffer.concat([iv,c.update(JSON.stringify(data)),c.final(),c.getAuthTag()]).toString('base64url');
}
export function unseal(value,key,now=Date.now()) {
  if(typeof value!=='string'||value.length>2048) throw Error('Invalid flow');
  const b=Buffer.from(value,'base64url'); if(b.length<29) throw Error('Invalid flow');
  const c=createDecipheriv('aes-256-gcm',Buffer.from(key,'hex'),b.subarray(0,12)); c.setAuthTag(b.subarray(-16));
  const p=JSON.parse(Buffer.concat([c.update(b.subarray(12,-16)),c.final()]));
  if(!validSecret(p.state)||!validSecret(p.verifier)||!Number.isSafeInteger(p.exp)||p.exp<=now||p.exp>now+600000) throw Error('Expired flow');
  return p;
}
export function verifyIdentity(token,jwks,{clientId,ownerId,now=Math.floor(Date.now()/1000)}) {
  if(typeof token!=='string'||token.length>16000) throw Error('Invalid ID token');
  const parts=token.split('.'); if(parts.length!==3||parts.some(p=>!p||!/^[A-Za-z0-9_-]+$/.test(p))) throw Error('Invalid token encoding');
  const [h,p,s]=parts, header=JSON.parse(Buffer.from(h,'base64url')), claims=JSON.parse(Buffer.from(p,'base64url'));
  if(header.alg!=='RS256'||typeof header.kid!=='string'||header.crit!==undefined) throw Error('Invalid algorithm');
  const keys=jwks.keys.filter(k=>k.kid===header.kid&&k.kty==='RSA'&&(!k.use||k.use==='sig')&&(!k.alg||k.alg==='RS256'));
  if(keys.length!==1||!verify('RSA-SHA256',Buffer.from(h+'.'+p),createPublicKey({key:keys[0],format:'jwk'}),Buffer.from(s,'base64url'))) throw Error('Invalid signature');
  if(claims.iss!==issuer||claims.aud!==clientId||typeof claims.sub!=='string'||!claims.sub||!Number.isSafeInteger(claims.exp)||claims.exp<=now||!Number.isSafeInteger(claims.iat)||claims.iat>now+60||claims.iat<now-600||(claims.nbf!==undefined&&(!Number.isSafeInteger(claims.nbf)||claims.nbf>now+30))) throw Error('Invalid claims');
  if(!((typeof claims.id==='number'&&Number.isSafeInteger(claims.id))||(typeof claims.id==='string'&&/^\d+$/.test(claims.id)))||String(claims.id)!==ownerId) throw Error('Account not allowed');
  return String(claims.id);
}
export function cookies(raw='') { const result=Object.create(null); for(const part of raw.split(';')) {const i=part.indexOf('='); if(i>0){const k=part.slice(0,i).trim(); if(Object.hasOwn(result,k)) result[k]=''; else result[k]=part.slice(i+1).trim();}} return result; }
export function cookie(name,value,age) {return name+'='+value+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+age;}
