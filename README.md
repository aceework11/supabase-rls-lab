# supabase-rls-lab

A small, runnable answer to one question: **what does Supabase Row Level Security actually
enforce, and where does AI-generated RLS go wrong?**

It contains a multi-tenant schema with a two-hop ownership graph, a policy set written the
way I believe policies should be written, a test suite that proves tenant isolation by
executing against a real Postgres rather than asserting it, and seven documented defects —
each one a policy that AI tooling produces, paired with the exploit that breaks it and the
test that catches it.

Everything runs locally. No accounts, no hosted project, no real keys.

## Run it

Prerequisites: Docker, [Deno](https://deno.com) 2.x, and Node (for `npx supabase`).

```sh
deno task db:start                       # local Supabase: db + api + auth only
npx supabase status -o env > .env        # the fixed local dev keys; not secrets
deno task verify                         # db reset → seed → full suite
```

Expected: `ok | 2 passed (22 steps) | 0 failed`. Run `deno task test` a second time
without a reset — the suite is idempotent and passes again.

**Windows note.** The stack is configured on ports 553xx rather than the CLI's default
543xx, because Hyper-V/WSL commonly reserves a block that swallows 54321–54325
(`netsh interface ipv4 show excludedportrange protocol=tcp` will show it). If 553xx is
reserved on your machine too, change the four ports in `supabase/config.toml`.

## What is in here

```
supabase/migrations/
  0001_schema.sql      tables, keys, indexes — no policies
  0002_policies.sql    every access decision in the repo
  0003_defects.sql     seven bad/fixed table pairs
scripts/seed.ts        four identities via the Admin API, plus data
tests/
  identities.ts        real GoTrue sign-ins; a service-role ground-truth client;
                       one direct-Postgres path for the defect that needs it
  isolation.test.ts    twelve tenant-isolation cases
  defects.test.ts      seven exploit-vs-fix cases
defects/NN-*/README.md analysis of each defect
```

### The schema

```
auth.users ──< memberships >── organizations ──< projects ──< invoices
                  (role)
```

`invoices` is reachable only by joining `projects → organizations → memberships`. One-hop
ownership (`auth.uid() = user_id`) is where AI-written RLS is usually correct. Two hops is
where it is usually not.

### What the isolation suite proves

| Case                                                                | Asserted on                          |
| ------------------------------------------------------------------- | ------------------------------------ |
| A member reads only their own org's projects                        | row set                              |
| Another org's invoice by id returns zero rows                       | row count                            |
| A user in no org sees an empty set everywhere                       | row counts                           |
| An anonymous client sees zero rows everywhere                       | row counts                           |
| A `count` aggregate covers only the caller's org                    | the aggregate                        |
| A table with RLS on and no policy returns nothing, even to a member | row count                            |
| Updating your own row persists                                      | **re-read as service role**          |
| Updating another org's row changes nothing                          | **0 rows affected, and re-read**     |
| Moving your row into another org: PostgREST rejects it, and a **direct connection** (no REST layer to mask the policy) is rejected by `WITH CHECK` itself | error `42501` on both paths, and re-read |
| A plain member cannot change their own membership role              | **0 rows affected, and re-read**     |
| A plain member cannot delete an invoice                             | **0 rows, and the row still exists** |
| Inserting a row into another org is rejected                        | error `42501`                        |

The bold ones are the point. A blocked `UPDATE` or `DELETE` through PostgREST is **not an
error** — it is `200` with an empty array, because zero rows matched the policy. A suite
that asserts "no error was thrown" passes against a completely open table. Every mutation
test here re-reads the row with an identity that can see it, and the one policy the REST
layer's own quirks can mask (see defect 03) is also tested through a direct connection.

### The seven defects

Each lives in `0003_defects.sql` as a `d0N_bad_*` / `d0N_fixed_*` pair, side by side, so
one test proves the exploit works on one and fails on the other in the same run.

| #  | Defect                                                      | Folder                                                              |
| -- | ----------------------------------------------------------- | ------------------------------------------------------------------- |
| 01 | Identity trusted from the request body instead of the JWT   | [defects/01](defects/01-identity-from-request-body/)                |
| 02 | No tenant column, so no policy can scope                    | [defects/02](defects/02-no-tenant-column/)                          |
| 03 | `WITH CHECK` weaker than `USING` on UPDATE                  | [defects/03](defects/03-with-check-weaker-than-using/)              |
| 04 | RLS is row-level, not column-level                          | [defects/04](defects/04-rls-is-not-column-level/)                   |
| 05 | `SECURITY DEFINER` function that skips the membership check | [defects/05](defects/05-security-definer-without-membership-check/) |
| 06 | Multiple permissive policies OR together                    | [defects/06](defects/06-permissive-policies-or-together/)           |
| 07 | The `service_role` key anywhere a client can reach          | [defects/07](defects/07-service-role-key-client-reachable/)         |

Defect 03 is the one to read if you read only one. Through Supabase's API the bad table is
unreachable by **three independent accidents** — PostgREST's `RETURNING` causes Postgres
to apply the SELECT policy to the new row; a WHERE-less RPC is refused by the `safeupdate`
preload; and both of those hide a `WITH CHECK` that would let a user move their row into
any tenant they can name. A direct server-side connection has none of those accidents. The
test walks all four paths.

## How this was built, honestly

This repository is being drafted with Claude Code, under my direction. That is not a
caveat; it is the point. The job of a senior engineer working with AI is not to avoid the
tool but to catch what it gets wrong before it ships — and RLS is where it gets things
wrong most confidently. I am working through `0002_policies.sql` policy by policy, and
writing each defect's analysis by hand as I go (see the note below on which ones are
done) — this file will say so plainly once that pass is finished, not before.

The rule during the build was: **no claim about Postgres behaviour gets written down until
it has been tested against the live database.** That rule overturned two things the model
stated with confidence and that I might otherwise have shipped:

1. _"An UPDATE policy without `WITH CHECK` lets a user move their row to another tenant."_
   False. Postgres reuses `USING` as the check when `WITH CHECK` is omitted. The real
   defect is an explicit `WITH CHECK` that is weaker than `USING` — which is what AI
   writes, on the reasoning that "USING already filtered the row".

2. _"That weak `WITH CHECK` is exploitable through a PostgREST update."_ Also false, and
   for a reason that took four experiments to isolate: Postgres applies the SELECT policy
   to the new row whenever the UPDATE reads the table. Then a fifth experiment found
   `safeupdate` blocking the WHERE-less path too. The hole is real; it is simply not
   reachable from where most people test.

The same discipline also caught something after the suite was already green. An earlier
draft of the `invoices` policies used a `SECURITY DEFINER` helper —
`project_org(project_id) returns org_id` — to reach the second hop of the ownership graph.
It looked correct and every test passed. It was still a real information-disclosure bug:
Supabase exposes any function the API role can execute as an RPC endpoint, so that helper
was directly callable by **any** authenticated user, for **any** project id, including
projects in an organisation they were never a member of — handing back that project's
`org_id` and completely bypassing `projects`' own RLS. A boolean helper like
`is_org_member` is safe to expose this way, because "am I a member of org X" isn't
sensitive on its own; a raw foreign-key resolver is not, because it hands back a piece of
a row the caller was never entitled to read. Confirmed with a direct probe — a user with
no access to Org B's project retrieved Org B's real org id — then fixed by removing the
helper and rewriting the four invoice policies as an inline `EXISTS` against `projects`,
which inherits that table's own RLS instead of bypassing it.

That is the failure mode this whole repository is about: a green test suite and a
plausible-looking policy are not the same thing as a secure one, and the only way to close
the gap is to keep attacking your own work after it already "works".

The defect analyses under `defects/` are written by me, in my own words, one at a time —
this repo is committed as each is finished rather than held back until all seven are
done, so the commit history reflects the actual pace of the work. A skeleton whose
`README.md` still opens with "Analysis not yet written" means exactly that: the SQL and
the test for that defect are real and passing, my write-up of it isn't there yet.

## Licence

MIT.
