# 06 — Multiple permissive policies OR together

- **SQL:** `d06_bad_docs / d06_fixed_docs` in
  [supabase/migrations/0003_defects.sql](../../supabase/migrations/0003_defects.sql)
- **Test:** `06 when a leftover permissive policy sits beside the scoped one` in
  [tests/defects.test.ts](../../tests/defects.test.ts)

## What the AI wrote, and why it looks right

```sql
create policy d06_bad_select_scoped on public.d06_bad_docs
  for select to authenticated using (public.is_org_member(org_id));
create policy "Enable read access for authenticated users" on public.d06_bad_docs
  for select to authenticated using ((select auth.uid()) is not null);
```

The first policy here is correct — it's the same `is_org_member` scoping used everywhere
else in this repo. If I only ever review the _newest_ policy added to a table, this table
looks fine: someone wrote the right one. The second policy is the tell: its name is the
literal default label Supabase's dashboard and several scaffolding tools generate for a
starter "authenticated users can read" policy. It's the kind of policy that gets created
early — during initial table setup, or by a generator — and then never revisited once the
"real" scoped policy is added later, because the table's `SELECT` behavior now looks
correct in every manual check anyone runs.

## How it breaks

Postgres evaluates multiple _permissive_ policies for the same table and command with
`OR`, not `AND`. A row is visible if it satisfies _any_ permissive policy that applies —
not all of them. So the presence of the scoped policy does nothing to constrain the
leftover one:

```ts
await carol.from("d06_bad_docs").select();
// -> returns Org A's doc, even though carol is only in Org B
```

The scoped policy correctly says "no" for Carol. The leftover policy separately says "yes,
you're logged in." Postgres ORs them, and the "yes" wins. This is the failure mode that
makes reviewing RLS by reading _one_ policy at a time dangerous — a table can carry an
arbitrary number of permissive policies, and the effective security is the weakest one
among all of them, not the strictest.

## The fix, and why this fix rather than another

```sql
create policy d06_fixed_select_scoped on public.d06_fixed_docs
  for select to authenticated using (public.is_org_member(org_id));
```

The fix is deletion, not addition — drop the leftover policy entirely rather than try to
tighten it or combine it with the scoped one. I didn't consider converting it to a
`RESTRICTIVE` policy instead (which Postgres ANDs together with permissive ones), because
that would mean carrying two policies doing overlapping work indefinitely, which is
exactly the kind of redundancy that caused this bug — the point isn't to make the extra
policy safe, it's that the table shouldn't have had it once a real scoped policy existed.

## How I catch it in review

For every table, I run `select * from pg_policies where tablename = '...'` — not just read
the migration file that added the policy I'm currently reviewing — and count how many
permissive policies exist per `(table, command)` pair. More than one is a review item
every time, regardless of how correct each individual one looks in isolation, because the
question that matters isn't "is this policy right," it's "is this policy right AND is it
the only thing granting access." I specifically look for auto-generated policy names —
"Enable read access for authenticated users," "Enable insert for authenticated users
only," and similar dashboard-default phrasing — because they're the strongest signal that
a scaffolding step never got cleaned up.
