# 02 — No tenant column, so no policy can scope

- **SQL:** `d02_bad_reports / d02_fixed_reports` in
  [supabase/migrations/0003_defects.sql](../../supabase/migrations/0003_defects.sql)
- **Test:** `02 when the table has no tenant column` in
  [tests/defects.test.ts](../../tests/defects.test.ts)

## What the AI wrote, and why it looks right

```sql
create table public.d02_bad_reports (
  id    uuid primary key default gen_random_uuid(),
  title text not null
);
alter table public.d02_bad_reports enable row level security;
create policy d02_bad_select on public.d02_bad_reports
  for select to authenticated using (auth.role() = 'authenticated');
```

This is the defect that looks the most "secure" from a distance, because every individual
step someone would check for is present: RLS is enabled, a policy exists, and the policy
does reference `auth`. It reads as intentional. The actual bug happened one step earlier,
at schema design — the table was never given an `org_id` (or any other ownership column) —
and by the time a policy gets written, there's nothing left to scope it against.
`auth.role() = 'authenticated'` is the only predicate that's still available to write, so
that's what gets written, and it technically compiles and technically "enforces"
something: it enforces that you're logged in. It doesn't enforce anything about _whose_
data you're logged in to see, because the schema never recorded whose data a row is.

## How it breaks

```ts
await carol.from("d02_bad_reports").select();
// -> returns Org A's report; carol has never been a member of Org A
```

Every authenticated user sees every row, because "authenticated" is the only fact the
policy has to check. RLS is doing exactly what it was told; what it was told to do just
isn't tenant isolation. This is the one defect in the set where the fix can't be a
different policy at all, because there's no column for a better policy to reference —
which is exactly why I think this is the most dangerous of the seven to leave undetected:
a reviewer scanning for "does this table have RLS enabled" and "does a policy exist" will
find both present and move on, and the missing column is easy to miss unless you
specifically ask what the policy is actually scoping against.

## The fix, and why this fix rather than another

```sql
create table public.d02_fixed_reports (
  id     uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  title  text not null
);
create index idx_d02_fixed_reports_org_id on public.d02_fixed_reports (org_id);
alter table public.d02_fixed_reports enable row level security;
create policy d02_fixed_select on public.d02_fixed_reports
  for select to authenticated using (public.is_org_member(org_id));
```

The fix is a schema change, not a policy change: add the `org_id` foreign key, index it
(every foreign key referenced by a policy predicate needs an index or every scoped query
on that table full-scans), and only then write the policy that was actually intended —
`is_org_member(org_id)`, the same helper used everywhere else in this repo. I didn't try
to retrofit a tenant boundary out of some other existing column (created- by timestamp
ranges, an inferred relationship through a different table) — a correctness argument built
on an indirect proxy for ownership is exactly the kind of fragile reasoning that's hard to
review later and easy to break with an unrelated change. A direct foreign key to the
tenant is the only version of this fix I'd sign off on.

## How I catch it in review

Before I read a single policy, I read the schema: does every table that's meant to be
tenant-scoped actually have a column a policy _could_ scope against? If a table has RLS
enabled and a policy that only checks `auth.role()` or `auth.uid() is not null` with no
reference to any ownership or tenant column, that's not a weak policy — it's very likely a
missing column being papered over by the only predicate left available. I treat "RLS is
on, and a policy exists" as the _start_ of a review, never as evidence that a table is
safe on its own.
