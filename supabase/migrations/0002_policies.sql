-- 0002_policies.sql
-- Every access decision in this repo is made here. There is no application layer,
-- deliberately: a hole in a policy cannot be hidden behind server-side code.
--
-- Two conventions used throughout, both of which AI-generated policies routinely miss:
--
--   1. UPDATE policies carry BOTH `using` and `with check`. `using` decides which
--      existing rows you may touch; `with check` decides what the row is allowed to
--      look like afterwards. Omit `with check` on a table whose tenant column is
--      writable and a user can move their own row into someone else's tenant.
--
--   2. Policies are scoped `to authenticated`. The `anon` role is never named by any
--      policy, so an unauthenticated request matches nothing and reads zero rows.
--      Note this is RLS-level denial, not grant-level: PostgREST returns 200 with an
--      empty array, NOT a 403. Tests assert on row counts for exactly that reason.

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------
--
-- A policy on `memberships` that itself selects from `memberships` recurses until
-- Postgres gives up (42P17, "infinite recursion detected in policy"). The standard
-- escape is a SECURITY DEFINER function: it runs as its owner, so the nested read is
-- not re-filtered by the calling user's policies.
--
-- SECURITY DEFINER is a loaded gun and is defect 05 in this repo. Three things make
-- this version safe, and all three are load-bearing:
--
--   * `set search_path = ''` — without it, a caller who can create objects in a
--     schema earlier on the search path can shadow `memberships` and make this
--     function answer from a table they control. Every identifier below is therefore
--     schema-qualified.
--   * `stable`, not `volatile` — lets the planner cache it per statement.
--   * execute revoked from public/anon, granted only to `authenticated`.

create or replace function public.is_org_member(p_org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.memberships m
    where m.org_id = p_org_id
      and m.user_id = (select auth.uid())
  );
$$;

create or replace function public.has_org_role(p_org_id uuid, p_roles public.org_role[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.memberships m
    where m.org_id = p_org_id
      and m.user_id = (select auth.uid())
      and m.role = any (p_roles)
  );
$$;

-- There is deliberately NO "project_org(project_id) returns org_id" helper here.
-- An earlier draft had one, granted to `authenticated` so the invoice policies below
-- could reach the second hop. It was an information-disclosure bug: PostgREST
-- exposes any function the API role can execute as an RPC endpoint, so that grant
-- made the helper directly callable by ANY authenticated user, for ANY project id —
-- including projects in an org they are not a member of — returning that project's
-- org_id and completely bypassing the `projects` table's own RLS. A boolean helper
-- like is_org_member is safe to expose this way because the answer to "am I a member
-- of org X" is not sensitive on its own; a raw foreign-key resolver is not, because
-- it hands back a piece of a row the caller was never authorised to read.
--
-- The invoice policies below reach the second hop with an EXISTS against `projects`
-- instead. That subquery runs as the calling role, so `projects`' own RLS still
-- applies inside it — a non-member's subquery sees zero rows and EXISTS is false,
-- with no separate function ever handing org_id to a caller who isn't already
-- entitled to see it.

revoke execute on function public.is_org_member(uuid) from public, anon;
revoke execute on function public.has_org_role(uuid, public.org_role[]) from public, anon;

grant execute on function public.is_org_member(uuid) to authenticated;
grant execute on function public.has_org_role(uuid, public.org_role[]) to authenticated;

-- ---------------------------------------------------------------------------
-- Enable RLS everywhere
-- ---------------------------------------------------------------------------
alter table public.organizations  enable row level security;
alter table public.memberships    enable row level security;
alter table public.projects       enable row level security;
alter table public.invoices       enable row level security;
alter table public.internal_notes enable row level security;

-- ---------------------------------------------------------------------------
-- organizations
-- ---------------------------------------------------------------------------
-- Read-only to members. Creating and renaming organisations is a service-role
-- operation on purpose: it is the kind of mutation that should live behind reviewed
-- server code, not be reachable by any authenticated client that guesses a payload.
create policy organizations_select_member
  on public.organizations
  for select
  to authenticated
  using (public.is_org_member(id));

-- ---------------------------------------------------------------------------
-- memberships
-- ---------------------------------------------------------------------------
-- Members see their co-members; only owners and admins may change the roster.
--
-- This is where RLS being ROW-level and not COLUMN-level bites. A naive
-- "members can update their own membership" policy looks like self-service and is
-- actually privilege escalation: the row contains `role`, so the user updates
-- themselves to 'owner'. That naive version is defect 04. Here, UPDATE is closed to
-- ordinary members entirely.
create policy memberships_select_member
  on public.memberships
  for select
  to authenticated
  using (public.is_org_member(org_id));

create policy memberships_insert_admin
  on public.memberships
  for insert
  to authenticated
  with check (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));

create policy memberships_update_admin
  on public.memberships
  for update
  to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]))
  with check (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));

create policy memberships_delete_admin
  on public.memberships
  for delete
  to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));

-- ---------------------------------------------------------------------------
-- projects
-- ---------------------------------------------------------------------------
create policy projects_select_member
  on public.projects
  for select
  to authenticated
  using (public.is_org_member(org_id));

-- `created_by` is pinned to the caller's own id rather than trusted from the request
-- body. A client can send any JSON it likes; auth.uid() comes from the verified JWT.
-- Trusting a client-supplied identity field is defect 01.
create policy projects_insert_member
  on public.projects
  for insert
  to authenticated
  with check (
    public.is_org_member(org_id)
    and created_by = (select auth.uid())
  );

-- `with check` mirrors `using` here, on purpose and explicitly.
--
-- A nuance worth knowing cold: OMITTING `with check` on an UPDATE policy is safe —
-- Postgres reuses the `using` expression as the check (verified empirically against
-- this database before writing this comment, not taken from memory). The hole is
-- an explicit `with check` that is WEAKER than `using`, e.g. `with check (true)`
-- or `with check (auth.uid() is not null)`, which AI writes constantly on the
-- reasoning that "using already filtered the row". It did — and then the check
-- approved moving that row into another tenant. That is defect 03.
create policy projects_update_member
  on public.projects
  for update
  to authenticated
  using (public.is_org_member(org_id))
  with check (public.is_org_member(org_id));

create policy projects_delete_admin
  on public.projects
  for delete
  to authenticated
  using (public.has_org_role(org_id, array['owner', 'admin']::public.org_role[]));

-- ---------------------------------------------------------------------------
-- invoices  (the two-hop table)
-- ---------------------------------------------------------------------------
-- Reading is open to any member of the owning org; writing is restricted to
-- owners and admins. Both reach the org via an EXISTS against `projects` — see the
-- comment above the helper functions for why this is an EXISTS and not a resolver
-- function.
create policy invoices_select_member
  on public.invoices
  for select
  to authenticated
  using (
    exists (
      select 1 from public.projects p
      where p.id = invoices.project_id
        and public.is_org_member(p.org_id)
    )
  );

create policy invoices_insert_admin
  on public.invoices
  for insert
  to authenticated
  with check (
    exists (
      select 1 from public.projects p
      where p.id = invoices.project_id
        and public.has_org_role(p.org_id, array['owner', 'admin']::public.org_role[])
    )
  );

create policy invoices_update_admin
  on public.invoices
  for update
  to authenticated
  using (
    exists (
      select 1 from public.projects p
      where p.id = invoices.project_id
        and public.has_org_role(p.org_id, array['owner', 'admin']::public.org_role[])
    )
  )
  with check (
    exists (
      select 1 from public.projects p
      where p.id = invoices.project_id
        and public.has_org_role(p.org_id, array['owner', 'admin']::public.org_role[])
    )
  );

create policy invoices_delete_admin
  on public.invoices
  for delete
  to authenticated
  using (
    exists (
      select 1 from public.projects p
      where p.id = invoices.project_id
        and public.has_org_role(p.org_id, array['owner', 'admin']::public.org_role[])
    )
  );

-- ---------------------------------------------------------------------------
-- internal_notes  — RLS enabled above, and intentionally given NO policy.
-- ---------------------------------------------------------------------------
-- Postgres RLS denies unless a policy permits. A legitimate, authenticated member of
-- the owning org still reads zero rows here. This is the safe direction to fail in,
-- and it is asserted by a test so that nobody "fixes" it later by accident.

-- PostgREST caches the schema; without this a freshly migrated table 404s from the
-- client and the failure looks like a broken test rather than a stale cache.
notify pgrst, 'reload schema';
