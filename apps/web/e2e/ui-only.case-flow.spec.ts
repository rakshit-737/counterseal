import { expect, test } from "@playwright/test";

/** These tests use route mocks only. They are UI-only and are not backend-integration tests. */
test.describe("UI-only route mocks — authenticated case flow", () => {
  test("validates a memory-only token and reads a mocked case", async ({ page }) => {
    await page.route("**/v1/me", async (route) => {
      await route.fulfill({ json: { subject: "ui-only.analyst", role: "analyst" } });
    });
    await page.route("**/v1/cases", async (route) => {
      await route.fulfill({ json: {
        items: [{
          case_id: "ui-case-1",
          title: "UI-only mocked case",
          description: "This row is a route mock for the browser shell.",
          state: "NEEDS_EVIDENCE",
          reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
          created_by: "ui-only.analyst",
          created_at: "2026-09-28T10:00:00Z",
          updated_at: "2026-09-28T10:00:00Z",
        }],
      } });
    });
    await page.route("**/v1/cases/ui-case-1", async (route) => {
      await route.fulfill({ json: {
        case_id: "ui-case-1",
        title: "UI-only mocked case",
        description: "This row is a route mock for the browser shell.",
        state: "NEEDS_EVIDENCE",
        reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
        created_by: "ui-only.analyst",
        created_at: "2026-09-28T10:00:00Z",
        updated_at: "2026-09-28T10:00:00Z",
      } });
    });
    await page.route("**/v1/cases/ui-case-1/timeline", async (route) => {
      await route.fulfill({ json: { items: [] } });
    });

    await page.goto("/");
    await page.getByLabel("Local bearer token").fill("ui-only-token");
    await page.getByRole("button", { name: "Validate token" }).click();
    await expect(page.getByText("UI-only mocked case")).toBeVisible();
    await expect(page.getByText("FIXTURE-VALIDATED—NOT PRODUCTION ASSURANCE")).toBeVisible();
  });

  test("shows the queue transport boundary using mocked 202 data", async ({ page }) => {
    const mockedCase = {
      case_id: "ui-case-2",
      title: "UI-only queue mock",
      description: "No security engine is available in this UI-only scenario.",
      state: "NEEDS_EVIDENCE",
      reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
      created_by: "ui-only.analyst",
      created_at: "2026-09-28T10:00:00Z",
      updated_at: "2026-09-28T10:00:00Z",
    };
    await page.route("**/v1/me", async (route) => route.fulfill({ json: { subject: "ui-only.analyst", role: "analyst" } }));
    await page.route("**/v1/cases", async (route) => route.fulfill({ json: { items: [mockedCase] } }));
    await page.route("**/v1/cases/ui-case-2", async (route) => route.fulfill({ json: mockedCase }));
    await page.route("**/v1/cases/ui-case-2/timeline", async (route) => route.fulfill({ json: { items: [] } }));
    await page.route("**/v1/cases/ui-case-2/investigations", async (route) => {
      expect(route.request().headers()["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/i);
      await route.fulfill({ status: 202, json: {
        job_id: "ui-job-2",
        case_id: "ui-case-2",
        kind: "INVESTIGATION",
        status: "QUEUED",
        reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
        requested_by: "ui-only.analyst",
        created_at: "2026-09-28T10:01:00Z",
        updated_at: "2026-09-28T10:01:00Z",
        attempts: 0,
        lease_expires_at: null,
        completed_at: null,
        outcome: null,
      } });
    });

    await page.goto("/");
    await page.getByLabel("Local bearer token").fill("ui-only-token");
    await page.getByRole("button", { name: "Validate token" }).click();
    await page.getByRole("button", { name: /UI-only queue mock/ }).click();
    await page.getByRole("button", { name: "Queue investigation request" }).click();
    await expect(page.getByText("Queue transport accepted")).toBeVisible();
    await expect(page.getByText(/No security engine runs in Phase 1/)).toBeVisible();
  });
});
