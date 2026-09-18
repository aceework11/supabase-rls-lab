# 05 — SECURITY DEFINER function that skips the membership check

- **SQL:** `d05_bad_org_total() / d05_fixed_org_total()` in
  [supabase/migrations/0003_defects.sql](../../supabase/migrations/0003_defects.sql)
- **Test:** `05 when a SECURITY DEFINER rpc skips the membership check` in
  [tests/defects.test.ts](../../tests/defects.test.ts)

## What the AI wrote, and why it looks right

```sql
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
```

This is the shape I expect to see the moment a dashboard total or aggregate needs to join
across a table that's protected by RLS. A plain `SECURITY INVOKER` function joining
`invoices` to `projects` under RLS often returns nothing useful, because the join's
intermediate rows get filtered per-caller in ways that don't compose cleanly across two
RLS-protected tables. The fast fix — and the one a model reaches for immediately — is
`security definer`: run the function as its owner, so RLS stops applying inside it, and
the join "just works." It compiles, it returns the right number for a legitimate caller,
and the ticket gets closed.

The part that's easy to miss: `security definer` doesn't just skip RLS on the two tables
being joined — it skips _any_ authorization check the function's body doesn't explicitly
perform itself. The function was never told to check whether the caller belongs to the org
it's being asked to total. It was only ever exercised by a caller who did belong, so that
gap never showed up.

## How it breaks

```ts
await carol.rpc("d05_bad_org_total", { p_org_id: orgA.id });
// -> Org A's real total, and Carol is a member of Org B, not Org A
```

Carol has zero relationship to Org A. She calls the function with Org A's id as a plain
argument, and gets back Org A's real revenue total. There's no error, no partial result,
no signal that anything went wrong — a `SECURITY DEFINER` function with no internal check
will answer for any input it's given, to any caller who's merely `authenticated`. This is
the same category of bug as `project_org()`, the resolver function I found and removed
from this repo's own "correct" policy set during a self-audit (see the root README) — a
definer function that hands back real data with no membership check is a bypass of every
RLS policy on the tables it touches, and PostgREST exposes any function the API role can
execute as a callable RPC endpoint, so the bypass is directly reachable by anyone with an
account.

## The fix, and why this fix rather than another

```sql
create or replace function public.d05_fixed_org_total(p_org_id uuid)
returns bigint
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not public.is_org_member(p_org_id) then
    raise exception 'not a member of this organisation' using errcode = '42501';
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
```

The fix keeps `security definer` — it's genuinely needed here to make the cross-table join
work — and adds back, by hand, the exact check RLS would have performed if it had been
able to: is the caller a member of the org being asked about. I reused `is_org_member()`
rather than writing a fresh membership query, because a second, slightly-different
membership check is exactly how these things drift out of sync with the real policies over
time. I also added `set search_path = ''`, which the bad version was missing — without it,
a caller who can create objects earlier on the default search path could shadow
`public.invoices` or `public.projects` and make this function read from a table they
control instead of the real ones.

The alternative I didn't take: converting the function back to `SECURITY INVOKER` and
fixing the join some other way (a view, a different join order). I considered it, but
`SECURITY DEFINER` plus an explicit check is the more honest artifact — it names the
authorization decision in one visible line rather than relying on the reader to trust that
RLS alone makes the join safe, which is precisely the false assumption that created this
defect in the first place.

## How I catch it in review

Every `security definer` function gets the same question before anything else: what stops
this from answering for an input the caller has no relationship to? If the answer isn't an
explicit check in the function body — usually a call to something like `is_org_member` or
`has_org_role` — the function is not secure regardless of what it's protecting. I also
check for `set search_path = ''` on every one of them; a definer function without it is a
second, independent way for the same kind of function to be turned against its own tables.
