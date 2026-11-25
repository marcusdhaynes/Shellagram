begin;
create schema if not exists shellagram;
revoke all on schema shellagram from public, anon, authenticated;
grant usage on schema shellagram to service_role;
create table if not exists shellagram.devices (
  token_hash text primary key check (token_hash ~ '^[a-f0-9]{64}$'),
  owner_id text not null,
  trusted boolean not null default false,
  active_until timestamptz not null,
  direct_until timestamptz not null,
  expires_at timestamptz not null,
  last_seen timestamptz not null default now()
);
create unique index if not exists sg_one_desktop on shellagram.devices(owner_id) where trusted;
alter table shellagram.devices enable row level security;
revoke all on shellagram.devices from public, anon, authenticated;
grant select, insert, update, delete on shellagram.devices to service_role;
create or replace function public.shellagram_transition(p_owner text,p_action text,p_hash text,p_new text default null)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare d shellagram.devices%rowtype; desk shellagram.devices%rowtype; t timestamptz; was_trusted boolean := false; active boolean := false;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('shellagram:' || p_owner,0));
  t := pg_catalog.clock_timestamp();
  delete from shellagram.devices where owner_id=p_owner and expires_at<=t;
  select * into d from shellagram.devices where owner_id=p_owner and token_hash=p_hash;
  active := coalesce(d.active_until>t,false);
  if p_action='login' then
    if p_new is null or p_new !~ '^[a-f0-9]{64}$' then raise exception 'Invalid token'; end if;
    was_trusted := coalesce(d.trusted,false);
    delete from shellagram.devices where owner_id=p_owner and token_hash=p_hash;
    insert into shellagram.devices(token_hash,owner_id,trusted,active_until,direct_until,expires_at,last_seen)
    values(p_new,p_owner,was_trusted,t+interval '12 hours',t+interval '10 minutes',t+case when was_trusted then interval '90 days' else interval '12 hours' end,t);
    update shellagram.devices set active_until=least(expires_at,t+interval '12 hours'),direct_until=t where owner_id=p_owner and trusted and token_hash<>p_new;
    p_hash:=p_new;
  elsif p_action='trust' then
    if not active or d.direct_until<=t then return jsonb_build_object('error','Fresh Telegram login required'); end if;
    delete from shellagram.devices where owner_id=p_owner and trusted and token_hash<>p_hash;
    update shellagram.devices set trusted=true,expires_at=t+interval '90 days' where token_hash=p_hash and owner_id=p_owner;
  elsif p_action='logout' then
    update shellagram.devices set active_until=t,direct_until=t where owner_id=p_owner and token_hash=p_hash and trusted;
    delete from shellagram.devices where owner_id=p_owner and token_hash=p_hash and not trusted;
  elsif p_action in ('lock-desktop','forget-desktop','lock-all') then
    if not active then return jsonb_build_object('error','Sign in first'); end if;
    if p_action='lock-desktop' then
      update shellagram.devices set active_until=t,direct_until=t where owner_id=p_owner and trusted;
    elsif p_action='forget-desktop' then
      delete from shellagram.devices where owner_id=p_owner and trusted;
    else
      update shellagram.devices set active_until=t,direct_until=t where owner_id=p_owner and trusted;
      delete from shellagram.devices where owner_id=p_owner and not trusted;
    end if;
  elsif p_action='status' then
    update shellagram.devices set last_seen=t where owner_id=p_owner and token_hash=p_hash and last_seen<t-interval '30 seconds';
  else raise exception 'Unknown operation'; end if;
  select * into d from shellagram.devices where owner_id=p_owner and token_hash=p_hash;
  select * into desk from shellagram.devices where owner_id=p_owner and trusted;
  active:=coalesce(d.active_until>t,false);
  return jsonb_build_object('signedIn',active,'trusted',coalesce(d.trusted,false),'fresh',active and coalesce(d.direct_until>t,false),'expiresAt',case when active then d.active_until else null end,
    'desktop',case when active then jsonb_build_object('paired',desk.token_hash is not null,'signedIn',coalesce(desk.active_until>t,false),'lastSeen',desk.last_seen,'trustExpires',desk.expires_at) else null end);
end; $$;
revoke all on function public.shellagram_transition(text,text,text,text) from public, anon, authenticated;
grant execute on function public.shellagram_transition(text,text,text,text) to service_role;
commit;
