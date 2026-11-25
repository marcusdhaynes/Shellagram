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

-- Rate limiting (stateless Edge Functions need DB-backed counters).
create table if not exists shellagram.rate_limits (
  bucket text not null,
  window_start timestamptz not null,
  hits integer not null default 0,
  primary key (bucket, window_start)
);
alter table shellagram.rate_limits enable row level security;
revoke all on shellagram.rate_limits from public, anon, authenticated;
grant select, insert, update, delete on shellagram.rate_limits to service_role;
create or replace function public.shellagram_rate_check(p_key text, p_limit integer, p_window_seconds integer)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare t timestamptz; w timestamptz; n integer;
begin
  if p_key is null or length(p_key) <> 64 or p_limit is null or p_limit < 1 or p_window_seconds is null or p_window_seconds < 1 or p_window_seconds > 86400 then raise exception 'Invalid rate limit request'; end if;
  t := pg_catalog.clock_timestamp();
  w := pg_catalog.to_timestamp(pg_catalog.floor(extract(epoch from t) / p_window_seconds) * p_window_seconds);
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('shellagram-rate:' || p_key, 0));
  insert into shellagram.rate_limits(bucket, window_start, hits) values (p_key, w, 1)
    on conflict (bucket, window_start) do update set hits = shellagram.rate_limits.hits + 1
    returning hits into n;
  if n = 1 then delete from shellagram.rate_limits where bucket = p_key and window_start < w; end if;
  if n > p_limit then
    return pg_catalog.jsonb_build_object('allowed', false, 'retryAfter', ceil(extract(epoch from (w + (p_window_seconds || ' seconds')::interval - t)))::integer);
  end if;
  return pg_catalog.jsonb_build_object('allowed', true, 'retryAfter', 0);
end; $$;
revoke all on function public.shellagram_rate_check(text,integer,integer) from public, anon, authenticated;
grant execute on function public.shellagram_rate_check(text,integer,integer) to service_role;
-- Replay prevention: a completed login flow (keyed by hash of its state) may be used once.
create table if not exists shellagram.used_flows (
  flow_hash text primary key check (flow_hash ~ '^[a-f0-9]{64}$'),
  expires_at timestamptz not null
);
alter table shellagram.used_flows enable row level security;
revoke all on shellagram.used_flows from public, anon, authenticated;
grant select, insert, delete on shellagram.used_flows to service_role;
create or replace function public.shellagram_use_flow(p_hash text)
returns boolean language plpgsql security invoker set search_path = '' as $$
declare t timestamptz; n integer := 0;
begin
  if p_hash is null or p_hash !~ '^[a-f0-9]{64}$' then raise exception 'Invalid flow hash'; end if;
  t := pg_catalog.clock_timestamp();
  delete from shellagram.used_flows where expires_at <= t;
  insert into shellagram.used_flows(flow_hash, expires_at) values (p_hash, t + interval '15 minutes')
    on conflict (flow_hash) do nothing;
  get diagnostics n = row_count;
  return n > 0;
end; $$;
revoke all on function public.shellagram_use_flow(text) from public, anon, authenticated;
grant execute on function public.shellagram_use_flow(text) to service_role;
commit;

-- Partner backend messages (added Nov 25, 2026)
begin;
create table if not exists shellagram.messages (
  tg_id bigint primary key,
  sender text not null,
  sent_at timestamptz not null,
  body text not null,
  deleted boolean not null default false
);
create index if not exists sg_messages_recent on shellagram.messages(sent_at desc) where not deleted;
alter table shellagram.messages enable row level security;
revoke all on shellagram.messages from public, anon, authenticated;
grant select, insert, update on shellagram.messages to service_role;
create or replace function public.shellagram_messages(p_owner text, p_hash text, p_limit integer default 100, p_before bigint default null, p_search text default null)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare t timestamptz; ok boolean;
begin
  if p_hash is null or p_hash !~ '^[a-f0-9]{64}$' then return pg_catalog.jsonb_build_object('signedIn', false, 'messages', '[]'::jsonb); end if;
  t := pg_catalog.clock_timestamp();
  select exists(select 1 from shellagram.devices where owner_id=p_owner and token_hash=p_hash and active_until>t) into ok;
  if not ok then return pg_catalog.jsonb_build_object('signedIn', false, 'messages', '[]'::jsonb); end if;
  return pg_catalog.jsonb_build_object('signedIn', true, 'messages', coalesce((
    select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', m.tg_id, 'from', m.sender, 'at', m.sent_at, 'text', m.body) order by m.tg_id desc)
    from (select tg_id, sender, sent_at, body from shellagram.messages
          where not deleted
            and (p_before is null or tg_id < p_before)
            and (p_search is null or p_search = '' or body ilike '%' || p_search || '%')
          order by tg_id desc limit pg_catalog.least(greatest(coalesce(p_limit,100),1),200)) m
  ), '[]'::jsonb));
end; $$;
revoke all on function public.shellagram_messages(text,text,integer,bigint,text) from public, anon, authenticated;
grant execute on function public.shellagram_messages(text,text,integer,bigint,text) to service_role;
create or replace function public.shellagram_delete_message(p_owner text, p_hash text, p_id bigint)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare t timestamptz; ok boolean; n integer := 0;
begin
  if p_hash is null or p_hash !~ '^[a-f0-9]{64}$' or p_id is null then return pg_catalog.jsonb_build_object('error','Sign in first'); end if;
  t := pg_catalog.clock_timestamp();
  select exists(select 1 from shellagram.devices where owner_id=p_owner and token_hash=p_hash and active_until>t) into ok;
  if not ok then return pg_catalog.jsonb_build_object('error','Sign in first'); end if;
  update shellagram.messages set deleted=true where tg_id=p_id and not deleted;
  get diagnostics n = row_count;
  return pg_catalog.jsonb_build_object('deleted', n > 0);
end; $$;
revoke all on function public.shellagram_delete_message(text,text,bigint) from public, anon, authenticated;
grant execute on function public.shellagram_delete_message(text,text,bigint) to service_role;
commit;
