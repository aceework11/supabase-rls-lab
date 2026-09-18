// tests/defects.test.ts
//
// One test per defect. Each proves BOTH directions in a single test body: the exploit
// succeeds against the `_bad` table and the identical exploit fails against `_fixed`.
// If either half rots, the test goes red — there is no way for a fix to quietly stop
// being tested.
//
// Every "succeeded" claim is confirmed by re-reading the row as service role. A 200
// from PostgREST is not evidence that a write landed.

import { assert, assertEquals, assertExists, assertRejects } from "@std/assert";
import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";
import { asDirectUser, asService, asUser, EMAILS, fixtures } from "./identities.ts";
import type { SupabaseClient } from "@supabase/supabase-js";

let alice: SupabaseClient;
let bob: SupabaseClient;
let carol: SupabaseClient;
let fx: Awaited<ReturnType<typeof fixtures>>;

beforeAll(async () => {
  [alice, bob, carol, fx] = await Promise.all([
    asUser(EMAILS.alice),
    asUser(EMAILS.bob),
    asUser(EMAILS.carol),
    fixtures(),
  ]);
});

afterAll(async () => {
  await Promise.all([alice.auth.signOut(), bob.auth.signOut(), carol.auth.signOut()]);
});

describe("defects: exploit succeeds on bad, fails on fixed", () => {
  it("01 when a client inserts a row attributed to another user, then bad accepts it and fixed rejects it", async () => {
    const spoof = { user_id: fx.userIds.carol, action: "spoofed-by-alice" };

    const bad = await alice.from("d01_bad_usage_log").insert(spoof);
    assertEquals(bad.error, null);
    const { data: landed } = await fx.svc
      .from("d01_bad_usage_log")
      .select()
      .eq("user_id", fx.userIds.carol)
      .eq("action", "spoofed-by-alice");
    assert(landed!.length >= 1, "bad: the spoofed row should have landed under carol");

    const fixed = await alice.from("d01_fixed_usage_log").insert(spoof);
    assertExists(fixed.error);
    assertEquals(fixed.error!.code, "42501");

    // keep the suite idempotent
    await fx.svc.from("d01_bad_usage_log").delete().eq("action", "spoofed-by-alice");
  });

  it("02 when the table has no tenant column, then bad leaks Org A's rows to Org B and fixed returns none", async () => {
    const bad = await carol.from("d02_bad_reports").select();
    assertEquals(bad.error, null);
    assert(bad.data!.length >= 1, "bad: carol (Org B) should see Org A's report");

    const fixed = await carol.from("d02_fixed_reports").select();
    assertEquals(fixed.error, null);
    assertEquals(fixed.data!.length, 0);
  });

  it("03 when WITH CHECK is weaker than USING, then every API path is blocked by accident, a direct connection moves the row on bad, and fixed holds", async () => {
    // Three API-reachable paths, three DIFFERENT accidental protections. A suite that
    // stops at any of them concludes the bad table is safe. It is not.

    // Path 1 — PostgREST update. PostgREST appends RETURNING; Postgres then applies
    // the SELECT policy to the returned row; alice cannot see Org B; 42501.
    const viaRest = await alice
      .from("d03_bad_projects")
      .update({ org_id: fx.orgB.id })
      .eq("org_id", fx.orgA.id);
    assertEquals(viaRest.error?.code, "42501");

    // Path 2 — an rpc doing `update ... set org_id = $1` with no WHERE and no
    // RETURNING, which is the shape that dodges Path 1's check. Blocked anyway, by
    // something else entirely: Supabase preloads `safeupdate` on the API role, which
    // refuses WHERE-less UPDATE/DELETE. SQLSTATE 21000.
    const viaRpc = await alice.rpc("d03_bad_move_all", { p_new_org: fx.orgB.id });
    assertEquals(viaRpc.error?.code, "21000");

    // Path 3 — a direct Postgres connection, which is what server-side code using a
    // pooled connection with `set local role` + JWT claims actually does. No
    // PostgREST, no RETURNING, no safeupdate. The only thing left is the policy —
    // and the policy's WITH CHECK is weak.
    const movedCount = await asDirectUser(fx.userIds.alice, async (tx) => {
      const r = await tx.unsafe(
        `update public.d03_bad_projects set org_id = $1`,
        [fx.orgB.id],
      );
      return r.count;
    });
    assertEquals(movedCount, 1);
    const { data: moved } = await fx.svc
      .from("d03_bad_projects")
      .select()
      .eq("name", "Atlas (d03 bad)")
      .single();
    assertEquals(moved!.org_id, fx.orgB.id);
    // restore for idempotency
    await fx.svc.from("d03_bad_projects").update({ org_id: fx.orgA.id }).eq(
      "name",
      "Atlas (d03 bad)",
    );

    // Same direct path against the fixed table: WITH CHECK mirrors USING, 42501.
    const err = await assertRejects(() =>
      asDirectUser(fx.userIds.alice, async (tx) => {
        await tx.unsafe(`update public.d03_fixed_projects set org_id = $1`, [fx.orgB.id]);
      })
    );
    assertEquals((err as { code?: string }).code, "42501");
    const { data: stayed } = await fx.svc
      .from("d03_fixed_projects")
      .select()
      .eq("name", "Atlas (d03 fixed)")
      .single();
    assertEquals(stayed!.org_id, fx.orgA.id);
  });

  it("04 when a self-service row policy covers a role column, then bad lets a member promote themselves and fixed denies the column", async () => {
    const bad = await bob
      .from("d04_bad_members")
      .update({ role: "owner" })
      .eq("user_id", fx.userIds.bob);
    assertEquals(bad.error, null);
    const { data: promoted } = await fx.svc
      .from("d04_bad_members")
      .select("role")
      .eq("user_id", fx.userIds.bob)
      .single();
    assertEquals(promoted!.role, "owner");
    await fx.svc.from("d04_bad_members").update({ role: "member" }).eq(
      "user_id",
      fx.userIds.bob,
    );

    const fixed = await bob
      .from("d04_fixed_members")
      .update({ role: "owner" })
      .eq("user_id", fx.userIds.bob);
    assertExists(fixed.error);
    assertEquals(fixed.error!.code, "42501");

    // and the column that IS self-service still works on the fixed table
    const allowed = await bob
      .from("d04_fixed_members")
      .update({ display_name: "Robert" })
      .eq("user_id", fx.userIds.bob);
    assertEquals(allowed.error, null);
    await fx.svc.from("d04_fixed_members").update({ display_name: "Bob" }).eq(
      "user_id",
      fx.userIds.bob,
    );
  });

  it("05 when a SECURITY DEFINER rpc skips the membership check, then bad answers for any org and fixed refuses", async () => {
    const bad = await carol.rpc("d05_bad_org_total", { p_org_id: fx.orgA.id });
    assertEquals(bad.error, null);
    assertEquals(Number(bad.data), 77_500); // Org A's real total, read by an Org B user

    const fixed = await carol.rpc("d05_fixed_org_total", { p_org_id: fx.orgA.id });
    assertExists(fixed.error);
    assertEquals(fixed.error!.code, "42501");

    // and a legitimate member still gets the number from the fixed version
    const ok = await alice.rpc("d05_fixed_org_total", { p_org_id: fx.orgA.id });
    assertEquals(ok.error, null);
    assertEquals(Number(ok.data), 77_500);
  });

  it("06 when a leftover permissive policy sits beside the scoped one, then bad leaks across tenants and fixed does not", async () => {
    const bad = await carol.from("d06_bad_docs").select();
    assertEquals(bad.error, null);
    assert(
      bad.data!.length >= 1,
      "bad: the OR'd scaffold policy should leak Org A's doc",
    );

    const fixed = await carol.from("d06_fixed_docs").select();
    assertEquals(fixed.error, null);
    assertEquals(fixed.data!.length, 0);
  });

  it("07 when the service_role key is used as a client, then every tenant is visible — and the key is nowhere in the repo", async () => {
    const svc = asService();
    const { count } = await svc.from("projects").select("*", {
      count: "exact",
      head: true,
    });
    assertEquals(count, 3); // all three, across both orgs, every policy ignored

    const key = Deno.env.get("SERVICE_ROLE_KEY")!;
    const offenders: string[] = [];
    for await (const entry of walk(".")) {
      const text = await Deno.readTextFile(entry);
      if (text.includes(key)) offenders.push(entry);
    }
    assertEquals(offenders, [], `service key found in: ${offenders.join(", ")}`);
  });
});

/** Text files in the repo, excluding the places a key is allowed or irrelevant. */
async function* walk(dir: string): AsyncGenerator<string> {
  const skip = new Set([".git", ".env", "node_modules", ".temp", ".branches"]);
  for await (const e of Deno.readDir(dir)) {
    if (skip.has(e.name) || e.name.endsWith(".log")) continue;
    const path = `${dir}/${e.name}`;
    if (e.isDirectory) yield* walk(path);
    else yield path;
  }
}
