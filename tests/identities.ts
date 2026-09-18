// tests/identities.ts
//
// Every test acts as a real, authenticated user holding a real JWT issued by GoTrue.
// Nothing here fakes a token or sets a claim by hand: the whole point is to exercise
// the same path a browser takes, so that what the tests prove is what production does.

import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import postgres from "postgres";

const URL = Deno.env.get("SUPABASE_URL") ?? "http://127.0.0.1:55321";
const ANON_KEY = Deno.env.get("ANON_KEY");
const SERVICE_ROLE_KEY = Deno.env.get("SERVICE_ROLE_KEY");

if (!ANON_KEY || !SERVICE_ROLE_KEY) {
  throw new Error(
    "ANON_KEY / SERVICE_ROLE_KEY missing. Run: npx supabase status -o env > .env",
  );
}

export const PASSWORD = "lab-password-not-a-secret";

export const EMAILS = {
  alice: "alice@lab.test", // Org A, owner
  bob: "bob@lab.test", // Org A, plain member
  carol: "carol@lab.test", // Org B, owner
  dave: "dave@lab.test", // no organisation
} as const;

const clientOpts = {
  auth: { autoRefreshToken: false, persistSession: false },
} as const;

/** An authenticated client carrying that user's own JWT. */
export async function asUser(email: string): Promise<SupabaseClient> {
  const client = createClient(URL, ANON_KEY!, clientOpts);
  const { error } = await client.auth.signInWithPassword({ email, password: PASSWORD });
  if (error) throw new Error(`sign-in failed for ${email}: ${error.message}`);
  return client;
}

/** No JWT at all. Matches no policy, so it should see nothing anywhere. */
export function asAnon(): SupabaseClient {
  return createClient(URL, ANON_KEY!, clientOpts);
}

/**
 * Bypasses RLS completely. Used ONLY to establish ground truth — to read the real
 * state of a row after a user was supposedly blocked from changing it.
 *
 * This is the load-bearing habit of the whole suite. A blocked UPDATE in PostgREST is
 * not an error: it returns 200 with an empty array, because zero rows matched the
 * policy's USING clause. A test that only asserts "no error was thrown" therefore
 * passes against a table with no security on it whatsoever. Proving a write did not
 * happen requires reading the row back with an identity that can actually see it.
 */
export function asService(): SupabaseClient {
  return createClient(URL, SERVICE_ROLE_KEY!, clientOpts);
}

/**
 * A direct Postgres connection acting as a specific user — the shape server-side
 * code takes when it holds a pooled connection and scopes it per request with
 * `set local role authenticated` plus the JWT claims. No PostgREST in the path, so
 * none of PostgREST's incidental protections (RETURNING, safeupdate) apply. Only the
 * policies do. Used by exactly one test, defect 03, because that defect is invisible
 * from every other path.
 *
 * Runs `fn` inside a transaction and commits. The caller restores state afterwards.
 */
export async function asDirectUser<T>(
  userId: string,
  fn: (tx: postgres.TransactionSql) => Promise<T>,
): Promise<T> {
  const url = Deno.env.get("DB_URL");
  if (!url) throw new Error("DB_URL missing. Run: npx supabase status -o env > .env");
  const sql = postgres(url, { max: 1, onnotice: () => {} });
  try {
    return await sql.begin(async (tx) => {
      await tx.unsafe(`set local role authenticated`);
      await tx`select set_config('request.jwt.claims', ${
        JSON.stringify({ sub: userId, role: "authenticated" })
      }, true)`;
      return await fn(tx);
    });
  } finally {
    await sql.end();
  }
}

/** Ground-truth fixture ids, read as service role. */
export async function fixtures() {
  const svc = asService();

  const { data: orgs, error: orgErr } = await svc.from("organizations").select();
  if (orgErr) throw orgErr;
  const { data: projects, error: projErr } = await svc.from("projects").select();
  if (projErr) throw projErr;
  const { data: invoices, error: invErr } = await svc.from("invoices").select();
  if (invErr) throw invErr;

  const { data: members, error: memErr } = await svc.from("memberships").select();
  if (memErr) throw memErr;

  const orgA = orgs.find((o) => o.name === "Northwind Labs")!;
  const orgB = orgs.find((o) => o.name === "Beacon Studio")!;
  const atlas = projects.find((p) => p.name === "Atlas Migration")!;
  const harbor = projects.find((p) => p.name === "Harbor Rollout")!;

  const userIds = {
    alice: members.find((m) => m.org_id === orgA.id && m.role === "owner")!.user_id,
    bob: members.find((m) => m.org_id === orgA.id && m.role === "member")!.user_id,
    carol: members.find((m) => m.org_id === orgB.id && m.role === "owner")!.user_id,
  };

  return {
    svc,
    orgA,
    orgB,
    atlas,
    harbor,
    userIds,
    atlasInvoice: invoices.find((i) => i.project_id === atlas.id)!,
    harborInvoice: invoices.find((i) => i.project_id === harbor.id)!,
  };
}
