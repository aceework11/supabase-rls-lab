-- 0001_schema.sql
-- Core multi-tenant schema. No policies here: 0002 owns every access decision.
--
-- The ownership graph is deliberately two hops deep:
--
--   auth.users --< memberships >-- organizations --< projects --< invoices
--                    (role)
--
-- `invoices` is reachable only by joining projects -> organizations -> memberships.
-- One-hop ownership (auth.uid() = user_id) is the case AI-generated RLS usually gets
-- right. Two hops is where it writes USING (true), or joins in the wrong direction,
-- or silently drops the tenant predicate. That is the case worth testing.

create extension if not exists pgcrypto;

create type public.org_role as enum ('owner', 'admin', 'member');

create table public.organizations (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  created_at timestamptz not null default now()
);

create table public.memberships (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references public.organizations (id) on delete cascade,
  user_id    uuid not null references auth.users (id) on delete cascade,
  role       public.org_role not null default 'member',
  created_at timestamptz not null default now(),
  unique (org_id, user_id)
);

create table public.projects (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references public.organizations (id) on delete cascade,
  name       text not null,
  created_by uuid not null references auth.users (id),
  created_at timestamptz not null default now()
);

create table public.invoices (
  id           uuid primary key default gen_random_uuid(),
  project_id   uuid not null references public.projects (id) on delete cascade,
  amount_cents integer not null check (amount_cents >= 0),
  status       text not null default 'draft'
               check (status in ('draft', 'sent', 'paid', 'void')),
  created_at   timestamptz not null default now()
);

-- Deny-by-default demonstrator. RLS is enabled on this table in 0002 and it is given
-- no policy, ever. A legitimate, authenticated member of the owning org still reads
-- zero rows from it. Postgres RLS denies unless a policy permits; there is no implicit
-- allow. One test asserts exactly this, because "we forgot to write the policy" is a
-- much safer failure than "we forgot to enable RLS".
create table public.internal_notes (
  id     uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  body   text not null
);

-- Indexes on foreign keys [engine: core/knowledge/web/database-patterns.md §3].
--
-- Note the deliberate omission: memberships.org_id is NOT indexed separately. The
-- unique (org_id, user_id) constraint already creates a btree whose leftmost prefix
-- is org_id, so a standalone index on org_id would be dead weight on every write.
-- memberships.user_id does need its own, because it is not a leftmost prefix of that
-- constraint and every is_org_member() call filters on it.
create index idx_memberships_user_id   on public.memberships (user_id);
create index idx_projects_org_id       on public.projects (org_id);
create index idx_projects_created_by   on public.projects (created_by);
create index idx_invoices_project_id   on public.invoices (project_id);
create index idx_internal_notes_org_id on public.internal_notes (org_id);
