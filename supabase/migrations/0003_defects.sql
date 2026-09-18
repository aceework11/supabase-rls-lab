-- 0003_defects.sql
--
-- Seven RLS defects that AI-generated policies produce, each as a PAIR of tables:
-- `d0N_bad_*` carries the defective policy, `d0N_fixed_*` the corrected one. Both
-- exist side by side so a single test can prove the exploit succeeds against one and
-- fails against the other, in the same run, with no teardown between.
--
-- The SQL here is the mechanism. The analysis of each — why AI produces it, how it
-- was caught in practice, what to look for in review — lives in defects/NN-*/README.md
-- and is written by hand.

-- ===========================================================================
-- 01  Identity trusted from the request body instead of the JWT
-- ===========================================================================
-- SELECT is scoped correctly, so the table LOOKS secure in every read test. INSERT
-- is `with check (true)`: any client can write a row attributed to any user_id it
-- likes. Quota counters, usage logs, audit trails — anything keyed by user — can be
-- spoofed onto someone else.
create table public.d01_bad_usage_log (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  action  text not null
);
alter table public.d01_bad_usage_log enable row level security;
create policy d01_bad_select on public.d01_bad_usage_log
  for select to authenticated using (user_id = (select auth.uid()));
create policy d01_bad_insert on public.d01_bad_usage_log
  for insert to authenticated with check (true);

create table public.d01_fixed_usage_log (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  action  text not null
);
alter table public.d01_fixed_usage_log enable row level security;
create policy d01_fixed_select on public.d01_fixed_usage_log
  for select to authenticated using (user_id = (select auth.uid()));
create policy d01_fixed_insert on public.d01_fixed_usage_log
  for insert to authenticated with check (user_id = (select auth.uid()));

-- ===========================================================================
-- 02  No tenant column at all, so no policy can scope
-- ===========================================================================
-- The generated schema forgot org_id. The generated policy then "secures" the table
-- with the only predicate available — is the caller logged in — and every tenant
-- reads every row. RLS is enabled, a policy exists, and nothing is protected.
create table public.d02_bad_reports (
  id    uuid primary key default gen_random_uuid(),
  title text not null
);
alter table public.d02_bad_reports enable row level security;
create policy d02_bad_select on public.d02_bad_reports
  for select to authenticated using (auth.role() = 'authenticated');

create table public.d02_fixed_reports (
  id     uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  title  text not null
);
create index idx_d02_fixed_reports_org_id on public.d02_fixed_reports (org_id);
alter table public.d02_fixed_reports enable row level security;
create policy d02_fixed_select on public.d02_fixed_reports
  for select to authenticated using (public.is_org_member(org_id));

-- ===========================================================================
-- 03  WITH CHECK weaker than USING on UPDATE
-- ===========================================================================
-- Omitting `with check` entirely is SAFE: Postgres reuses `using`. The hole is an
-- explicit check that is looser than the filter. `using` confirms the row is
-- currently yours; `with check (auth.uid() is not null)` confirms only that you are
-- logged in. Result: you may move your own row into any tenant you can name.
create table public.d03_bad_projects (
  id     uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  name   text not null
);
alter table public.d03_bad_projects enable row level security;
create policy d03_bad_select on public.d03_bad_projects
  for select to authenticated using (public.is_org_member(org_id));
create policy d03_bad_update on public.d03_bad_projects
  for update to authenticated
  using (public.is_org_member(org_id))
  with check ((select auth.uid()) is not null);

create table public.d03_fixed_projects (
  id     uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  name   text not null
);
alter table public.d03_fixed_projects enable row level security;
create policy d03_fixed_select on public.d03_fixed_projects
  for select to authenticated using (public.is_org_member(org_id));
create policy d03_fixed_update on public.d03_fixed_projects
  for update to authenticated
  using (public.is_org_member(org_id))
  with check (public.is_org_member(org_id));

-- The part that makes 03 dangerous rather than academic — and the reason a naive
-- test suite passes against the bad table.
--
-- Postgres has a second, undocumented-feeling safety net: when an UPDATE needs
-- SELECT permission on the table (a WHERE on its columns, a RETURNING clause, a SET
-- reading a column) the SELECT policy is ALSO applied to the new row. The mover
-- cannot see the row in its new org, so it fails with 42501. PostgREST always adds
-- RETURNING, so through the REST API the bad table looks safe. Verified all four
-- shapes against this database before writing this:
--
--     update t set org_id = $1 where name = '...'   -> 42501  (WHERE reads table)
--     update t set org_id = $1 where id = id        -> 42501  (WHERE reads table)
--     update t set org_id = $1 returning id         -> 42501  (RETURNING reads table)
--     update t set org_id = $1                      -> UPDATE 1   <- the hole
--
-- The hole is an UPDATE that reads nothing: no WHERE, no RETURNING, scoped only by
-- the policy's USING — the shape of a "move all my projects to org X" rpc written by
-- someone who trusts RLS to be the WHERE clause. These two SECURITY INVOKER functions
-- are that rpc. And through Supabase's API they are ALSO blocked, by a third layer:
-- the `authenticator` role preloads `safeupdate`, which refuses WHERE-less
-- UPDATE/DELETE with SQLSTATE 21000. So the rpcs exist here to prove that layer.
--
-- What finally reaches the policy is a direct Postgres connection — server code
-- holding a pooled connection and scoping it with `set local role authenticated` plus
-- the JWT claims, which is a normal thing for a Supabase backend to do. No PostgREST,
-- no RETURNING, no safeupdate. The test's third path is that connection, and on the
-- bad table it moves the row.
--
-- Three accidental protections is not a security model. It is three reasons the bug
-- was never noticed.
create or replace function public.d03_bad_move_all(p_new_org uuid)
returns integer
language plpgsql
security invoker
set search_path = ''
as $$
declare n integer;
begin
  -- No WHERE on purpose: "RLS scopes it to my rows anyway."
  update public.d03_bad_projects set org_id = p_new_org;
  get diagnostics n = row_count;
  return n;
end;
$$;

create or replace function public.d03_fixed_move_all(p_new_org uuid)
returns integer
language plpgsql
security invoker
set search_path = ''
as $$
declare n integer;
begin
  update public.d03_fixed_projects set org_id = p_new_org;
  get diagnostics n = row_count;
  return n;
end;
$$;
grant execute on function public.d03_bad_move_all(uuid) to authenticated;
grant execute on function public.d03_fixed_move_all(uuid) to authenticated;

-- ===========================================================================
-- 04  RLS is row-level. It is not column-level.
-- ===========================================================================
-- "Users may edit their own membership" is a perfectly correct ROW policy. The row
-- contains `role`. So the user edits their own role to 'owner'. The fix is not a
-- better policy — no policy can see columns — it is a column-level GRANT: revoke
-- UPDATE on the table, grant it back on the columns that are actually self-service.
create table public.d04_bad_members (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references public.organizations (id) on delete cascade,
  user_id      uuid not null references auth.users (id) on delete cascade,
  role         public.org_role not null default 'member',
  display_name text not null default ''
);
alter table public.d04_bad_members enable row level security;
create policy d04_bad_select on public.d04_bad_members
  for select to authenticated using (user_id = (select auth.uid()));
create policy d04_bad_update on public.d04_bad_members
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create table public.d04_fixed_members (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references public.organizations (id) on delete cascade,
  user_id      uuid not null references auth.users (id) on delete cascade,
  role         public.org_role not null default 'member',
  display_name text not null default ''
);
alter table public.d04_fixed_members enable row level security;
create policy d04_fixed_select on public.d04_fixed_members
  for select to authenticated using (user_id = (select auth.uid()));
create policy d04_fixed_update on public.d04_fixed_members
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));
-- Same row policy as the bad table. The difference is entirely here:
revoke update on public.d04_fixed_members from authenticated;
grant  update (display_name) on public.d04_fixed_members to authenticated;

-- ===========================================================================
-- 05  SECURITY DEFINER function that skips the membership check
-- ===========================================================================
-- An RPC "to make the dashboard total work" is marked SECURITY DEFINER because the
-- join under RLS returned nothing. Now it runs as its owner, RLS no longer applies
-- inside it, and it answers for any org_id the caller passes. The fix is the same
-- function with the membership check the policies would have applied — and the
-- search_path pinned, and execute granted narrowly.
create or replace function public.d05_bad_org_total(p_org_id uuid)
returns bigint
language sql
stable
security definer
as $$
  select coalesce(sum(i.amount_cents), 0)::bigint
  from public.invoices i
  join public.projects p on p.id = i.project_id
  where p.org_id = p_org_id;
$$;
grant execute on function public.d05_bad_org_total(uuid) to authenticated;

create or replace function public.d05_fixed_org_total(p_org_id uuid)
returns bigint
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_org_member(p_org_id) then
    raise exception 'not a member of this organisation'
      using errcode = '42501';
  end if;
  return (
    select coalesce(sum(i.amount_cents), 0)::bigint
    from public.invoices i
    join public.projects p on p.id = i.project_id
    where p.org_id = p_org_id
  );
end;
$$;
revoke execute on function public.d05_fixed_org_total(uuid) from public, anon;
grant  execute on function public.d05_fixed_org_total(uuid) to authenticated;

-- ===========================================================================
-- 06  Multiple permissive policies OR together
-- ===========================================================================
-- Permissive policies on the same table and command are combined with OR. The
-- scoped policy is correct. The scaffold policy generated earlier — the dashboard
-- template literally called "Enable read access for authenticated users" — was
-- never removed. Any one weak policy defeats every strong one beside it.
create table public.d06_bad_docs (
  id     uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  title  text not null
);
create index idx_d06_bad_docs_org_id on public.d06_bad_docs (org_id);
alter table public.d06_bad_docs enable row level security;
create policy d06_bad_select_scoped on public.d06_bad_docs
  for select to authenticated using (public.is_org_member(org_id));
create policy "Enable read access for authenticated users" on public.d06_bad_docs
  for select to authenticated using ((select auth.uid()) is not null);

create table public.d06_fixed_docs (
  id     uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  title  text not null
);
create index idx_d06_fixed_docs_org_id on public.d06_fixed_docs (org_id);
alter table public.d06_fixed_docs enable row level security;
create policy d06_fixed_select_scoped on public.d06_fixed_docs
  for select to authenticated using (public.is_org_member(org_id));

-- ===========================================================================
-- 07  The service_role key anywhere a client can reach
-- ===========================================================================
-- Not a policy defect: no table pair can show it. The service role bypasses RLS by
-- design. The test for this one demonstrates what that key does when held by a
-- client — every tenant's rows, every policy ignored — and then scans this repo to
-- prove the key appears nowhere outside the gitignored .env.

notify pgrst, 'reload schema';
