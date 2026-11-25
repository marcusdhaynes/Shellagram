-- Run after setup.sql on the dedicated test database; all test rows roll back.
begin;
do $$
declare o text := 'shellagram-test-' || gen_random_uuid()::text; d text := repeat('a',64); m text := repeat('b',64); n text := repeat('c',64); s jsonb;
begin
  if exists(select 1 from shellagram.devices where token_hash in(d,m,n)) then raise exception 'Test hash collision'; end if;
  s := public.shellagram_transition(o,'status',d); if s->>'signedIn' <> 'false' then raise exception 'Unknown device signed in'; end if;
  s := public.shellagram_transition(o,'login','',d); if s->>'signedIn' <> 'true' then raise exception 'Login failed'; end if;
  s := public.shellagram_transition(o,'trust',d); if s->>'trusted' <> 'true' then raise exception 'Trust failed'; end if;
  s := public.shellagram_transition(o,'logout',d); if s->>'signedIn' <> 'false' or s->>'trusted' <> 'true' then raise exception 'Desktop lock failed'; end if;
  s := public.shellagram_transition(o,'login','',m); if s->>'signedIn' <> 'true' then raise exception 'Mobile login failed'; end if;
  s := public.shellagram_transition(o,'status',d); if s->>'signedIn' <> 'true' or s->>'fresh' <> 'false' then raise exception 'Desktop automatic unlock failed'; end if;
  s := public.shellagram_transition(o,'status',n); if s->>'signedIn' <> 'false' then raise exception 'Unpaired device unlocked'; end if;
  s := public.shellagram_transition(o,'lock-desktop',m); s := public.shellagram_transition(o,'status',d); if s->>'signedIn' <> 'false' then raise exception 'Remote lock failed'; end if;
  s := public.shellagram_transition(o,'login',m,n); s := public.shellagram_transition(o,'status',m); if s->>'signedIn' <> 'false' then raise exception 'Old mobile credential survived'; end if;
  s := public.shellagram_transition(o,'forget-desktop',n); s := public.shellagram_transition(o,'status',d); if s->>'trusted' <> 'false' then raise exception 'Forget failed'; end if;
  s := public.shellagram_transition(o,'lock-all',n); if s->>'signedIn' <> 'false' then raise exception 'Lock all failed'; end if;
  if has_function_privilege('anon','public.shellagram_transition(text,text,text,text)','EXECUTE') or has_function_privilege('authenticated','public.shellagram_transition(text,text,text,text)','EXECUTE') then raise exception 'Public RPC access'; end if;
end $$;

do $$
declare o text := 'shellagram-test-' || gen_random_uuid()::text;
  a text := repeat('a',64); b text := repeat('b',64); cc text := repeat('c',64);
  e text := repeat('e',64); f text := repeat('f',64); g text := repeat('1',64);
  s jsonb; r jsonb; i int;
begin
  -- rate limiting: 3 allowed, 4th denied with retryAfter; buckets independent
  for i in 1..3 loop
    r := public.shellagram_rate_check(e, 3, 600);
    if (r->>'allowed') <> 'true' then raise exception 'Rate check % should allow', i; end if;
  end loop;
  r := public.shellagram_rate_check(e, 3, 600);
  if (r->>'allowed') <> 'false' or (r->>'retryAfter')::int <= 0 then raise exception 'Rate check should deny with retryAfter'; end if;
  r := public.shellagram_rate_check(g, 3, 600);
  if (r->>'allowed') <> 'true' then raise exception 'Rate buckets not independent'; end if;
  -- replay store: first use passes, second is rejected
  if not public.shellagram_use_flow(f) then raise exception 'First flow use should pass'; end if;
  if public.shellagram_use_flow(f) then raise exception 'Second flow use should fail (replay)'; end if;
  -- permissions on new objects: deny-all for anon/authenticated, RLS on
  if has_function_privilege('anon','public.shellagram_rate_check(text,integer,integer)','EXECUTE') or has_function_privilege('authenticated','public.shellagram_rate_check(text,integer,integer)','EXECUTE') then raise exception 'Rate RPC public access'; end if;
  if has_function_privilege('anon','public.shellagram_use_flow(text)','EXECUTE') or has_function_privilege('authenticated','public.shellagram_use_flow(text)','EXECUTE') then raise exception 'Flow RPC public access'; end if;
  if has_table_privilege('anon','shellagram.rate_limits','SELECT') or has_table_privilege('authenticated','shellagram.used_flows','SELECT') or has_table_privilege('anon','shellagram.devices','SELECT') then raise exception 'Table public access'; end if;
  if not (select relrowsecurity from pg_class where oid='shellagram.rate_limits'::regclass) then raise exception 'rate_limits RLS off'; end if;
  if not (select relrowsecurity from pg_class where oid='shellagram.used_flows'::regclass) then raise exception 'used_flows RLS off'; end if;
  if not (select relrowsecurity from pg_class where oid='shellagram.devices'::regclass) then raise exception 'devices RLS off'; end if;
  -- trust requires a fresh login
  s := public.shellagram_transition(o,'login','',a);
  update shellagram.devices set direct_until = clock_timestamp() - interval '1 minute' where token_hash=a;
  s := public.shellagram_transition(o,'trust',a);
  if s->>'error' is null then raise exception 'Trust without fresh login allowed'; end if;
  -- one trusted desktop: trusting a second browser replaces the first
  s := public.shellagram_transition(o,'login',a,cc);
  s := public.shellagram_transition(o,'trust',cc); if s->>'trusted' <> 'true' then raise exception 'Trust A failed'; end if;
  s := public.shellagram_transition(o,'login','',b);
  s := public.shellagram_transition(o,'trust',b); if s->>'trusted' <> 'true' then raise exception 'Trust B failed'; end if;
  s := public.shellagram_transition(o,'status',cc);
  if s->>'trusted' <> 'false' then raise exception 'Second trust did not replace first desktop'; end if;
  -- lock-all deactivates everything
  s := public.shellagram_transition(o,'lock-all',b);
  if s->>'signedIn' <> 'false' then raise exception 'Lock-all failed (extended)'; end if;
  s := public.shellagram_transition(o,'status',cc);
  if s->>'signedIn' <> 'false' then raise exception 'Lock-all left desktop active'; end if;
  -- expiry purge: an expired device row is removed and never signs in
  insert into shellagram.devices(token_hash,owner_id,trusted,active_until,direct_until,expires_at,last_seen)
    values (repeat('d',64), o, false, clock_timestamp()+interval '1 hour', clock_timestamp(), clock_timestamp()-interval '1 minute', clock_timestamp());
  s := public.shellagram_transition(o,'status',repeat('d',64));
  if s->>'signedIn' <> 'false' then raise exception 'Expired device signed in'; end if;
  if exists(select 1 from shellagram.devices where token_hash=repeat('d',64)) then raise exception 'Expired device not purged'; end if;
end $$;
rollback;
