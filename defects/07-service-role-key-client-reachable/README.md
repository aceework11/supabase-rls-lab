# 07 — The service_role key anywhere a client can reach

- **SQL:** no table pair — see below for why
- **Test:** `07 when the service_role key is used as a client` in
  [tests/defects.test.ts](../../tests/defects.test.ts)

## What the AI wrote, and why it looks right

This defect doesn't have a `d0N_bad_*` / `d0N_fixed_*` pair, because it isn't a policy bug
— it's the one failure mode that makes every policy in this repo irrelevant at once. The
pattern I've seen an AI assistant produce, almost always while "just trying to get
something working quickly," is a client-side call — a browser script, a mobile app config,
occasionally a checked-in `.env.example` with a real value left in it by mistake —
constructed with `SUPABASE_SERVICE_ROLE_KEY` instead of the anon key. It looks like it
works, often _better_ than the anon-keyed version, because RLS errors that were blocking
the feature during development simply stop happening. That's the entire appeal, and it's
also the entire problem.

## How it breaks

```ts
const svc = createClient(url, SERVICE_ROLE_KEY);
const { count } = await svc.from("projects").select("*", { count: "exact", head: true });
// -> 3 — every project, across every org, regardless of who's asking
```

The service role key doesn't get a _more generous_ set of RLS policies applied to it — it
bypasses RLS entirely, by design, because Supabase's own server-side tooling (Edge
Functions, scheduled jobs, admin scripts) needs an unrestricted path to the database.
Every policy this repo tests — the two-hop `EXISTS` on invoices, the `WITH CHECK` scoping
on projects, all of it — assumes the request is arriving as `anon` or `authenticated`.
None of it applies once that key is in play. If it reaches a browser, a mobile bundle, or
any environment a user can inspect (view-source, a decompiled APK, browser devtools'
network tab), every tenant's data is one API call away for anyone who finds it, and none
of the other six defects in this repo matter anymore — this one supersedes all of them.

## The fix, and why this fix rather than another

There's no schema fix, because this was never a schema bug. The fix is process: the
service role key exists only in environments a client can't reach — server-side functions,
CI secrets, a `.env` that's gitignored and never bundled into anything shipped to a device
— and every test in this repo that needs elevated access (`asService()` in
`tests/identities.ts`) uses it strictly to establish ground truth for assertions, never to
simulate what a real user can do. I considered whether to add an automated check that
fails CI if the key appears in a client bundle, and decided the more valuable thing for
this repo specifically was to write the check as a runtime _test_, not a lint rule, so
it's exercised the same way every other defect here is — proven, not just declared:

```ts
const key = Deno.env.get("SERVICE_ROLE_KEY")!;
for await (const entry of walk(".")) {
  const text = await Deno.readTextFile(entry);
  if (text.includes(key)) offenders.push(entry);
}
assertEquals(offenders, []);
```

This walks every tracked text file in the repo and fails if the real key ever appears
outside the one gitignored `.env` it's meant to live in.

## How I catch it in review

Any code review that touches Supabase client construction gets one specific question
before anything else: which key is this, and does this code run somewhere a user could see
it run? `SERVICE_ROLE_KEY` (or `SUPABASE_SERVICE_ROLE_KEY`) has no legitimate reason to
appear in anything that ships to a browser, a mobile build, or a public repository —
including example files, since I've watched a real placeholder value get copy-pasted as if
it were safe simply because the variable name said "example." I grep for the key's
presence across a repo the same way the automated test here does, not just read the one
file under review, because a leaked key doesn't need to be in the file someone's currently
looking at to be live.
