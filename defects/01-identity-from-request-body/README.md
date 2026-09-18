# 01 — Identity trusted from the request body instead of the JWT

- **SQL:** `d01_bad_usage_log / d01_fixed_usage_log` in
  [supabase/migrations/0003_defects.sql](../../supabase/migrations/0003_defects.sql)
- **Test:** `01 when a client inserts a row attributed to another user` in
  [tests/defects.test.ts](../../tests/defects.test.ts)

## What the AI wrote, and why it looks right

The generated policy set for a usage-log table is:

```sql
create policy d01_bad_select on public.d01_bad_usage_log
  for select to authenticated using (user_id = (select auth.uid()));
create policy d01_bad_insert on public.d01_bad_usage_log
  for insert to authenticated with check (true);
```

This passes almost any review that only checks the read side. `SELECT` is scoped correctly
— a user genuinely can only ever see their own rows, and every read test you throw at it
passes. The problem is entirely on `INSERT`, and it's the kind of gap that's easy to miss
because nobody thinks to test "can I write a row I don't own" when the SELECT policy
already looks airtight.

I've seen the real version of this bug before it ever showed up in this lab. On a
production build, a rate-limiting Edge Function trusted a `user_id` field the client sent
in the request body instead of deriving it from the caller's JWT. The one real caller in
the codebase never even sent that field, so every request resolved to
`userId = 'anonymous'`. Because the `user_id` column was
`NOT NULL REFERENCES
auth.users(id)`, every quota write threw a type-cast error — which a
`try/catch` swallowed silently. The rate limit never fired in production, and the tests
stayed green because the mock database had no foreign-key or type enforcement to catch the
mismatch. Same root cause as this defect: identity taken from something the client
controls instead of something the server verified.

## How it breaks

`with check (true)` on `INSERT` means the check always passes, regardless of what
`user_id` value the row carries. `auth.uid()` is never referenced. Any authenticated user
can insert a row naming _any_ `user_id`, including another real user's id:

```ts
await alice.from("d01_bad_usage_log").insert({
  user_id: carolsId,
  action: "spoofed-by-alice",
});
```

That insert succeeds. The row lands under Carol's `user_id`, even though Carol never made
the request — Alice did. For a usage log this pollutes analytics and quota counters. For
anything audit-shaped — "who approved this," "who deleted this" — it's a way to frame
someone else for an action they didn't take, and there is no error anywhere in the flow to
notice.

## The fix, and why this fix rather than another

```sql
create policy d01_fixed_insert on public.d01_fixed_usage_log
  for insert to authenticated with check (user_id = (select auth.uid()));
```

The fix is one predicate: the row's `user_id` must equal the caller's own verified id. I
didn't reach for a trigger or an application-layer check instead, because both would
duplicate logic RLS already exists to hold, and both are bypassable by anything that talks
to Postgres directly without going through the app (a script, a different service, a
future integration). The policy is the single place this rule can never be skipped,
regardless of which client hits the table.

The one thing worth naming explicitly: I did _not_ make `user_id` a generated/default
column (e.g. `default auth.uid()`) instead of a check. A default is silently overridden if
the client's insert names the column at all — Postgres uses the client's value, not the
default, when one is supplied. `with check` is the only mechanism that actually _rejects_
a mismatched value rather than quietly ignoring it.

## How I catch it in review

I no longer trust a `SELECT` policy to tell me anything about a table's `INSERT` or
`UPDATE` safety — they're independent grants, and a table can be airtight to read and wide
open to write. When I review a new table's RLS, I read every `for insert` and `for update`
policy and ask one question of each: does this `with check` reference `auth.uid()`, or
does it reference nothing at all? `with check (true)` — or, just as commonly, no
`with check` clause paired with a table whose `INSERT` grant exists — is the single
pattern I search for first, because it's the one an AI model produces most often: it
correctly scopes reads, then treats the insert as "authenticated users can create their
own records" without ever encoding what "their own" means at the database level.
