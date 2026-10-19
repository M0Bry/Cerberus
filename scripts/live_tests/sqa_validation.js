/**
 * E2E: client-side validation sweep (JS validation, no security breakage).
 * Verifies each form blocks bad input with inline errors BEFORE any API
 * call, and that valid input still flows end-to-end.
 */
const { chromium } = require("playwright-core");

const BASE = "http://localhost:3000";
const results = [];
const check = (name, ok, detail = "") => {
  results.push({ name, ok });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  " + detail : ""}`);
};

(async () => {
  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  const page = await (await browser.newContext()).newPage();
  const email = `val_${Date.now()}@cerberus-test.com`;

  // ── 1. Register: bad email blocked client-side, no API call ──────────
  const reqs = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/v1/auth/register")) reqs.push(r);
  });
  await page.goto(BASE + "/register");
  await page.fill('input[name="name"]', "Test User");
  await page.fill('input[name="company"]', "ACME");
  await page.fill('input[name="title"]', "CISO");
  await page.fill('input[name="email"]', "not-an-email");
  await page.fill('input[name="password"]', "Cerberus123");
  await page.fill('input[name="confirm"]', "Cerberus123");
  await page.setInputFiles('input[type="file"]', "/tmp/sqa_e2e/photo.png");
  await page.click("button.rc-submit");
  await page.waitForTimeout(400);
  const alertText = (await page.textContent("#regAlert")).trim();
  check("register: bad email blocked", alertText === "Enter a valid email address.", alertText);
  check("register: no API call fired", reqs.length === 0, `calls=${reqs.length}`);

  // ── 2. Register: weak password blocked ───────────────────────────────
  await page.fill('input[name="email"]', email);
  await page.fill('input[name="password"]', "weak");
  await page.fill('input[name="confirm"]', "weak");
  await page.click("button.rc-submit");
  await page.waitForTimeout(300);
  check(
    "register: weak password blocked",
    (await page.textContent("#regAlert")).toLowerCase().includes("at least 8"),
    (await page.textContent("#regAlert")).trim()
  );

  // ── 3. Register: password mismatch blocked ───────────────────────────
  await page.fill('input[name="password"]', "Cerberus123");
  await page.fill('input[name="confirm"]', "Cerberus456");
  await page.click("button.rc-submit");
  await page.waitForTimeout(300);
  check(
    "register: mismatch blocked",
    (await page.textContent("#regAlert")).includes("do not match"),
    (await page.textContent("#regAlert")).trim()
  );

  // ── 4. Register: valid data still works end-to-end ───────────────────
  await page.fill('input[name="confirm"]', "Cerberus123");
  await page.click("button.rc-submit");
  await page.waitForTimeout(1200);
  check("register: valid flow reaches /verify-email", page.url().includes("/verify-email"), page.url());

  // ── 5. Login: bad email blocked ──────────────────────────────────────
  await page.goto(BASE + "/login");
  await page.fill('input[type="email"]', "nope");
  await page.fill('input[type="password"]', "Cerberus123");
  await page.click(".auth-panel button.btn-primary");
  await page.waitForTimeout(300);
  const loginErr = (await page.textContent(".alert")).trim();
  check("login: bad email blocked", loginErr === "Enter a valid email address.", loginErr);

  // ── 6. Contact: empty → name error; bad email → email error ─────────
  await page.goto(BASE + "/contact");
  await page.click('button[type="submit"]');
  await page.waitForTimeout(300);
  check("contact: empty blocked (name)", (await page.textContent('[role="alert"]')).includes("Name is required"));
  const inputs = page.locator("form .cyber-input");
  await inputs.nth(0).fill("Test Person");
  await inputs.nth(1).fill("bad");
  await page.click('button[type="submit"]');
  await page.waitForTimeout(300);
  check("contact: bad email blocked", (await page.textContent('[role="alert"]')).includes("valid email"));

  // ── 7. Contact: valid message reaches the admin inbox ────────────────
  await inputs.nth(1).fill(email);
  await inputs.nth(2).fill("Validation check");
  await inputs.nth(3).fill("This is a validation E2E message (10+ chars).");
  const contactReqs = [];
  page.on("request", (r) => {
    if (r.url().includes("/public/contact")) contactReqs.push(r);
  });
  await page.click('button[type="submit"]');
  await page.waitForTimeout(1200);
  check("contact: success state shown", (await page.textContent("body")).includes("message has been sent"));
  check("contact: API was called", contactReqs.length === 1, `calls=${contactReqs.length}`);

  // ── 8. Admin login: bad email blocked client-side, no API call ───────
  await page.goto(BASE + "/admin/login");
  const adminReqs = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/v1/admin/login")) adminReqs.push(r);
  });
  await page.fill("#adm-email", "nope");
  await page.fill("#adm-password", "x");
  await page.click('button[type="submit"]');
  await page.waitForTimeout(300);
  const adminBody = await page.textContent("body");
  check("admin login: inline error shown", adminBody.includes("Enter a valid email address"), "");
  check("admin login: no API call fired", adminReqs.length === 0, `calls=${adminReqs.length}`);

  await browser.close();
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} validation checks passed`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => {
  console.error("E2E crashed:", e.message);
  process.exit(2);
});
