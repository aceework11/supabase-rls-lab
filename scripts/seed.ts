// scripts/seed.ts
//
// Seeds the four identities and their data.
//
// Auth users are created through the Admin API rather than by inserting into
// auth.users directly. Hand-written inserts into auth.users are a well-known way to
// waste an afternoon: the column set and the password hashing scheme are GoTrue's
// private business and both have changed across versions. A seed that works today
// and breaks on the reviewer's machine is worse than no seed.
//
// Run: deno task seed   (after `supabase start` and `deno task db:reset`)

import { createClient } from "@supabase/supabase-js";

const URL = Deno.env.get("SUPABASE_URL") ?? "http://127.0.0.1:55321";
const SERVICE_KEY = Deno.env.get("SERVICE_ROLE_KEY");

if (!SERVICE_KEY) {
  console.error(
    "SERVICE_ROLE_KEY is not set.\n" +
      "Run:  npx supabase status -o env > .env  (then source it, or use `deno task seed`)",
  );
  Deno.exit(1);
}

// The service-role client bypasses RLS entirely. That is correct for a seeder and is
// exactly why this key never belongs anywhere a browser can reach it — see defect 07.
const admin = createClient(URL, SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

export const PASSWORD = "lab-password-not-a-secret";

export const USERS = {
  alice: { email: "alice@lab.test", note: "Org A, owner" },
  bob: { email: "bob@lab.test", note: "Org A, plain member" },
  carol: { email: "carol@lab.test", note: "Org B, owner" },
  dave: { email: "dave@lab.test", note: "no organisation at all" },
} as const;

type UserKey = keyof typeof USERS;

async function upsertUser(email: string): Promise<string> {
  // createUser fails loudly if the address already exists, so clear it first. This
  // keeps the seed idempotent: `deno task seed` twice in a row gives the same state.
  const { data: list, error: listErr } = await admin.auth.admin.listUsers();
  if (listErr) throw listErr;

  const existing = list.users.find((u) => u.email === email);
  if (existing) {
    const { error } = await admin.auth.admin.deleteUser(existing.id);
    if (error) throw error;
  }

  const { data, error } = await admin.auth.admin.createUser({
    email,
    password: PASSWORD,
    email_confirm: true, // no inbox round-trip in a local lab
  });
  if (error) throw error;
  return data.user.id;
}

async function main() {
  // Wipe domain data FIRST. projects.created_by references auth.users without a
  // cascade (an audit column should not vanish silently), so users cannot be deleted
  // while their projects exist. Organizations cascade to everything else.
  const { error: wipeErr } = await admin
    .from("organizations")
    .delete()
    .neq("id", "00000000-0000-0000-0000-000000000000");
  if (wipeErr) throw wipeErr;

  const ids = {} as Record<UserKey, string>;
  for (const [key, { email }] of Object.entries(USERS)) {
    ids[key as UserKey] = await upsertUser(email);
    console.log(`user  ${email.padEnd(16)} ${ids[key as UserKey]}`);
  }

  const { data: orgs, error: orgErr } = await admin
    .from("organizations")
    .insert([{ name: "Northwind Labs" }, { name: "Beacon Studio" }])
    .select();
  if (orgErr) throw orgErr;

  const orgA = orgs.find((o) => o.name === "Northwind Labs")!;
  const orgB = orgs.find((o) => o.name === "Beacon Studio")!;

  const { error: memErr } = await admin.from("memberships").insert([
    { org_id: orgA.id, user_id: ids.alice, role: "owner" },
    { org_id: orgA.id, user_id: ids.bob, role: "member" },
    { org_id: orgB.id, user_id: ids.carol, role: "owner" },
    // dave is deliberately in nothing.
  ]);
  if (memErr) throw memErr;

  const { data: projects, error: projErr } = await admin
    .from("projects")
    .insert([
      { org_id: orgA.id, name: "Atlas Migration", created_by: ids.alice },
      { org_id: orgA.id, name: "Orbit Redesign", created_by: ids.alice },
      { org_id: orgB.id, name: "Harbor Rollout", created_by: ids.carol },
    ])
    .select();
  if (projErr) throw projErr;

  const atlas = projects.find((p) => p.name === "Atlas Migration")!;
  const orbit = projects.find((p) => p.name === "Orbit Redesign")!;
  const harbor = projects.find((p) => p.name === "Harbor Rollout")!;

  const { error: invErr } = await admin.from("invoices").insert([
    { project_id: atlas.id, amount_cents: 250_00, status: "sent" },
    { project_id: atlas.id, amount_cents: 400_00, status: "draft" },
    { project_id: orbit.id, amount_cents: 125_00, status: "paid" },
    { project_id: harbor.id, amount_cents: 900_00, status: "sent" },
  ]);
  if (invErr) throw invErr;

  const { error: noteErr } = await admin.from("internal_notes").insert([
    { org_id: orgA.id, body: "Org A internal note. No policy grants access to this." },
    { org_id: orgB.id, body: "Org B internal note. Same." },
  ]);
  if (noteErr) throw noteErr;

  // Defect fixtures. Each pair gets identical Org A data so the only variable between
  // bad and fixed is the policy. d01 stays empty: its exploit is an INSERT.
  const defectRows: Array<[string, Record<string, unknown>]> = [
    ["d02_bad_reports", { title: "Org A quarterly numbers" }],
    ["d02_fixed_reports", { org_id: orgA.id, title: "Org A quarterly numbers" }],
    ["d03_bad_projects", { org_id: orgA.id, name: "Atlas (d03 bad)" }],
    ["d03_fixed_projects", { org_id: orgA.id, name: "Atlas (d03 fixed)" }],
    ["d04_bad_members", {
      org_id: orgA.id,
      user_id: ids.bob,
      role: "member",
      display_name: "Bob",
    }],
    ["d04_fixed_members", {
      org_id: orgA.id,
      user_id: ids.bob,
      role: "member",
      display_name: "Bob",
    }],
    ["d06_bad_docs", { org_id: orgA.id, title: "Org A roadmap" }],
    ["d06_fixed_docs", { org_id: orgA.id, title: "Org A roadmap" }],
  ];
  for (const [table, row] of defectRows) {
    const { error } = await admin.from(table).insert(row);
    if (error) throw new Error(`${table}: ${error.message}`);
  }

  console.log(
    `\norgs 2 · memberships 3 · projects 3 · invoices 4 · internal_notes 2` +
      `\nOrg A (Northwind Labs) ${orgA.id}` +
      `\nOrg B (Beacon Studio)  ${orgB.id}`,
  );
}

if (import.meta.main) {
  await main();
}
