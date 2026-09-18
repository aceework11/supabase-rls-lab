# 03 — WITH CHECK weaker than USING on UPDATE

- **SQL:** `d03_bad_projects / d03_fixed_projects, d03_*_move_all()` in
  [supabase/migrations/0003_defects.sql](../../supabase/migrations/0003_defects.sql)
- **Test:** `03 when WITH CHECK is weaker than USING` in
  [tests/defects.test.ts](../../tests/defects.test.ts)

## What the AI wrote, and why it looks right

```sql
create policy d03_bad_update on public.d03_bad_projects
  for update to authenticated
  using (public.is_org_member(org_id))
  with check ((select auth.uid()) is not null);
```

This is the single subtlest defect in the whole set, and I want to be precise about where
the actual bug is, because the obvious-looking version of this story is wrong. It is
**not** true that omitting `with check` is the hole — I tested that claim against a live
database before believing it, and Postgres reuses `using` as the check when `with check`
is left off. An `UPDATE` policy with only `using` is safe.

The real bug is an _explicit_ `with check` that is weaker than `using`. Here, `using`
correctly confirms the caller is a member of the project's current org before letting them
touch the row at all. But the `with check` — the clause that governs what the row is
allowed to look like _after_ the update — only confirms the caller is logged in. It looks
like reasonable belt-and-suspenders code: "I already checked membership in `using`, so
`with check` just needs to confirm they're a real user." That reasoning is exactly the
trap. `using` checks the row _before_ the write; `with check` governs the row _after_ it.
They are not the same predicate evaluated twice, and treating them as redundant is how a
tenant-crossing write gets through.

## How it breaks

If I test this the obvious way — through the REST API — it looks safe:

```ts
await alice.from("d03_bad_projects").update({ org_id: orgB.id }).eq("org_id", orgA.id);
// -> 42501, blocked
```

That's a false negative, and figuring out _why_ it's false is the actual finding here.
PostgREST always appends `RETURNING` to an `UPDATE`. Postgres then applies the table's
`SELECT` policy to the row being returned — and since the row now belongs to Org B, Alice
(a member only of Org A) can't see it, so the whole statement fails with 42501. The weak
`with check` never even gets exercised; a completely different policy caught it by
accident.

I confirmed this by testing three more shapes directly against Postgres: an `UPDATE` with
a `WHERE` clause, one with `RETURNING`, and one with neither. Only the one with **no
`WHERE` and no `RETURNING`** actually succeeds and moves the row — because that's the only
shape that never triggers Postgres's incidental "apply SELECT policy to the touched row"
behavior. Supabase's own `safeupdate` extension then blocks _that_ shape too, when it goes
through the API, by refusing any `WHERE`-less `UPDATE`/`DELETE` outright (SQLSTATE
`21000`).

So there are three independent, accidental layers standing in front of this bug when it's
only ever tested through the public API — and none of them are the policy. The one path
that reaches the real `with check` is a direct Postgres connection: the shape server code
takes when it holds a pooled connection and scopes it with `set local role
authenticated`
plus the caller's JWT claims, which is completely normal for backend code to do. No
PostgREST, no `RETURNING`, no `safeupdate`. Against that path, the weak `with check` waves
the row straight into Org B.

## The fix, and why this fix rather than another

```sql
create policy d03_fixed_update on public.d03_fixed_projects
  for update to authenticated
  using (public.is_org_member(org_id))
  with check (public.is_org_member(org_id));
```

`with check` mirrors `using` exactly. I considered just deleting the `with check` clause
entirely and relying on Postgres's documented fallback — but I kept it explicit on
purpose. An explicit, identical `with check` states the intent in the policy itself, so a
future reader (or a future AI edit) doesn't have to know the fallback rule exists to
understand why the table is safe. Relying on an implicit behavior that most engineers —
and most models — don't know about is a fragile thing to build security on.

## How I catch it in review

Three-part checklist I now run on every `UPDATE` policy: read `using` and `with
check`
side by side and ask whether they express the _same_ constraint, or whether `with check`
has quietly been given a weaker one. Then, regardless of what the answer looks like, I
don't trust a test written only against the REST API to prove it either way — I've now
seen this exact policy pass a naive test suite while carrying a real hole. Any `UPDATE`
policy that touches a column used for tenant/ownership scoping gets tested through a
direct database connection, not just through PostgREST, precisely because PostgREST's own
conventions (`RETURNING`) can mask a broken `with check` by accident.
