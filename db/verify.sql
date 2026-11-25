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
rollback;
