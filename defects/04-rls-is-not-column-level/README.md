# 04 — RLS is row-level, not column-level

- **SQL:** `d04_bad_members / d04_fixed_members` in
  [supabase/migrations/0003_defects.sql](../../supabase/migrations/0003_defects.sql)
- **Test:** `04 when a self-service row policy covers a role column` in
  [tests/defects.test.ts](../../tests/defects.test.ts)

## What the AI wrote, and why it looks right

```sql
create policy d04_bad_update on public.d04_bad_members
  for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));
```

Read purely as a row-ownership policy, this is _correct_. A member can only update a
membership row that's theirs — `using` and `with check` agree, both reference
`auth.uid()`, and there's no tenant-crossing hole like defect 03. If the request that
generated this was "let members edit their own membership record" — think a display name,
a notification preference — this is exactly the policy I'd expect, and it would pass a
review that only asks "can a user touch someone else's row."

The gap is that the request usually isn't that specific, and the table it gets applied to
carries more than the one self-service field. `d04_bad_members` has a `role` column on the
_same row_ the policy just approved for update.

## How it breaks

```ts
await bob.from("d04_bad_members").update({ role: "owner" }).eq("user_id", bobsId);
// -> succeeds; Bob is now recorded as 'owner'
```

RLS policies operate on rows, not columns. `using`/`with check` can restrict _which_ row
you're allowed to touch — they cannot restrict _which columns_ of that row you're allowed
to change. Bob genuinely owns the row being updated (it's his own membership), so the
policy has nothing to say about the fact that he just changed his `role` from `member` to
`owner`. From the database's point of view this is indistinguishable from him updating his
own display name. This is privilege escalation through a policy that is, on its own terms,
entirely correct.

## The fix, and why this fix rather than another

```sql
-- Same row policy as the bad table.
revoke update on public.d04_fixed_members from authenticated;
grant  update (display_name) on public.d04_fixed_members to authenticated;
```

The fix is not a better `using`/`with check` — there isn't one, because no row-level
predicate can see inside the row to say "this column may change, that one may not." The
fix has to happen one level up, in Postgres's column-level `GRANT` system: revoke blanket
`UPDATE` on the table from `authenticated`, then grant `UPDATE` back scoped to only the
columns that are genuinely self-service. The row policy stays exactly as it was — it's
still correct for _which row_, it was just never the right tool for _which column_.

I didn't reach for a trigger that rejects a `role` change from a non-admin instead,
because a `GRANT` is enforced earlier and more simply: an update statement naming a column
the caller has no privilege on is rejected outright by Postgres before RLS policies are
even evaluated, with no function to write, test, or keep in sync with the schema if a new
sensitive column gets added later and someone forgets to guard it in a trigger.

## How I catch it in review

Any `UPDATE` policy that's scoped by row ownership (`user_id = auth.uid()`, roughly) on a
table that also has a privilege-bearing column — `role`, `is_admin`, `tier`, anything that
changes what the row's owner is _allowed to do elsewhere_ — is a defect until I've checked
the `GRANT`s, not just the policy. The question I ask isn't "can this user touch this
row," it's "given that they can touch this row, which of its columns can they actually
change" — and if the answer is "all of them, because the policy allowed the row," that's
this bug.
