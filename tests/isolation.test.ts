// tests/isolation.test.ts
//
// The core tenant-isolation suite. Twelve cases, each named in three parts — what is
// tested, under what circumstances, what is expected — so a failure is diagnosable
// from the runner output without opening the file.
//
// House rule, applied without exception: a mutation test asserts the POST-STATE, not
// the absence of an error. See the comment on asService() in identities.ts for why
// that distinction is the difference between a real suite and a decorative one.

import { assertEquals, assertExists, assertNotEquals, assertRejects } from "@std/assert";
import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";
import { asAnon, asDirectUser, asUser, EMAILS, fixtures } from "./identities.ts";
import type { SupabaseClient } from "@supabase/supabase-js";

let alice: SupabaseClient;
let bob: SupabaseClient;
let carol: SupabaseClient;
let dave: SupabaseClient;
let fx: Awaited<ReturnType<typeof fixtures>>;

beforeAll(async () => {
  [alice, bob, carol, dave, fx] = await Promise.all([
    asUser(EMAILS.alice),
    asUser(EMAILS.bob),
    asUser(EMAILS.carol),
    asUser(EMAILS.dave),
    fixtures(),
  ]);
});

afterAll(async () => {
  // Cleanup after ALL tests, never after each: keeps the data inspectable when
  // something failed, and lets the suite run in parallel later.
  await Promise.all([
    alice.auth.signOut(),
    bob.auth.signOut(),
    carol.auth.signOut(),
    dave.auth.signOut(),
  ]);
});

describe("reading across tenants", () => {
  it("when a member of Org A reads projects, then only Org A's projects are returned", async () => {
    const { data, error } = await alice.from("projects").select();

    assertEquals(error, null);
    assertEquals(data!.length, 2);
    assertEquals(data!.every((p) => p.org_id === fx.orgA.id), true);
  });

  it("when a member of Org B reads Org A's invoice by id, then zero rows are returned", async () => {
    const { data, error } = await carol
      .from("invoices")
      .select()
      .eq("id", fx.atlasInvoice.id);

    assertEquals(error, null);
    assertEquals(data!.length, 0);
  });

  it("when a user belonging to no organisation reads any table, then every result is empty", async () => {
    const [orgs, projects, invoices] = await Promise.all([
      dave.from("organizations").select(),
      dave.from("projects").select(),
      dave.from("invoices").select(),
    ]);

    assertEquals(orgs.data!.length, 0);
    assertEquals(projects.data!.length, 0);
    assertEquals(invoices.data!.length, 0);
  });

  it("when an anonymous client reads any table, then every result is empty", async () => {
    const anon = asAnon();

    const [orgs, projects, invoices] = await Promise.all([
      anon.from("organizations").select(),
      anon.from("projects").select(),
      anon.from("invoices").select(),
    ]);

    assertEquals(orgs.data!.length, 0);
    assertEquals(projects.data!.length, 0);
    assertEquals(invoices.data!.length, 0);
  });

  it("when a member counts invoices, then the aggregate covers only their own org", async () => {
    // Aggregates are a classic blind spot: a policy can be correct for `select *` and
    // still leak totals if nobody ever tested count/sum.
    const { count, error } = await alice
      .from("invoices")
      .select("*", { count: "exact", head: true });

    assertEquals(error, null);
    assertEquals(count, 3); // Org A: two on Atlas, one on Orbit. Org B's is not counted.
  });

  it("when RLS is enabled on a table with no policy, then even a legitimate member reads zero rows", async () => {
    const { data, error } = await alice.from("internal_notes").select();

    assertEquals(error, null);
    assertEquals(data!.length, 0);
  });
});

describe("writing across tenants", () => {
  it("when a member updates their own org's project, then the change is persisted", async () => {
    const newName = "Atlas Migration";

    const { error } = await alice
      .from("projects")
      .update({ name: newName })
      .eq("id", fx.atlas.id);
    assertEquals(error, null);

    const { data: after } = await fx.svc
      .from("projects")
      .select()
      .eq("id", fx.atlas.id)
      .single();
    assertEquals(after!.name, newName);
  });

  it("when a member updates another org's project, then zero rows change and the row is untouched", async () => {
    const { data: before } = await fx.svc
      .from("projects")
      .select()
      .eq("id", fx.harbor.id)
      .single();

    const { data: affected, error } = await alice
      .from("projects")
      .update({ name: "seized by Org A" })
      .eq("id", fx.harbor.id)
      .select();

    // Not an error. Zero rows matched the USING clause, so PostgREST returns 200 [].
    assertEquals(error, null);
    assertEquals(affected!.length, 0);

    const { data: after } = await fx.svc
      .from("projects")
      .select()
      .eq("id", fx.harbor.id)
      .single();
    assertEquals(after!.name, before!.name);
    assertNotEquals(after!.name, "seized by Org A");
  });

  it("when a member moves their own project into another org, then it is rejected through PostgREST AND through a direct connection", async () => {
    // Through PostgREST this is rejected — but NOT by the policy's WITH CHECK.
    // PostgREST appends RETURNING, so Postgres applies the SELECT policy to the new
    // row, alice cannot see Org B, 42501. The mutation pass proved it: weakening the
    // WITH CHECK to (true) left this half of the test green. So this half documents
    // the masking; it does not test the policy.
    const viaRest = await alice
      .from("projects")
      .update({ org_id: fx.orgB.id })
      .eq("id", fx.atlas.id);
    assertEquals(viaRest.error?.code, "42501");

    // This half tests the policy. A direct connection, no WHERE, no RETURNING — the
    // only thing standing between alice and Org B is WITH CHECK. Weaken it and this
    // assertion goes red.
    const err = await assertRejects(() =>
      asDirectUser(fx.userIds.alice, async (tx) => {
        await tx.unsafe(`update public.projects set org_id = $1`, [fx.orgB.id]);
      })
    );
    assertEquals((err as { code?: string }).code, "42501");

    const { data: after } = await fx.svc
      .from("projects")
      .select()
      .eq("id", fx.atlas.id)
      .single();
    assertEquals(after!.org_id, fx.orgA.id);
  });

  it("when a plain member updates their own membership role, then zero rows change and the role is unchanged", async () => {
    // bob is 'member'. The row is his, and RLS is row-level — so a naive self-service
    // policy would let him write role='owner'. The real policy restricts UPDATE on
    // memberships to owners and admins, so his own row is not updatable by him at all.
    const { data: affected, error } = await bob
      .from("memberships")
      .update({ role: "owner" })
      .eq("user_id", fx.userIds.bob)
      .select();

    assertEquals(error, null);
    assertEquals(affected!.length, 0);

    const { data: after } = await fx.svc
      .from("memberships")
      .select("role")
      .eq("user_id", fx.userIds.bob)
      .single();
    assertEquals(after!.role, "member");
  });

  it("when a plain member deletes an invoice, then zero rows change and the invoice survives", async () => {
    // bob is role 'member' in Org A. He can READ this invoice; he may not delete it.
    const { data: affected, error } = await bob
      .from("invoices")
      .delete()
      .eq("id", fx.atlasInvoice.id)
      .select();

    assertEquals(error, null);
    assertEquals(affected!.length, 0);

    const { data: after } = await fx.svc
      .from("invoices")
      .select()
      .eq("id", fx.atlasInvoice.id)
      .maybeSingle();
    assertExists(after);
  });

  it("when a member inserts a project naming another org, then WITH CHECK rejects it", async () => {
    const { error } = await alice
      .from("projects")
      .insert({ org_id: fx.orgB.id, name: "trojan", created_by: fx.atlas.created_by });

    assertExists(error);
    assertEquals(error!.code, "42501");
  });
});
