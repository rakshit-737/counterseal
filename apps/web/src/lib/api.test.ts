import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient, createIdempotencyKey } from "./api";

function response(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, text: async () => typeof body === "string" ? body : JSON.stringify(body) } as Response;
}

afterEach(() => vi.restoreAllMocks());

describe("same-origin API client", () => {
  it("preserves the stable API error envelope without exposing arbitrary bodies", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => response({ error: { code: "FORBIDDEN", message: "Reader access is required." } }, 403)));
    await expect(createApiClient("memory-token").listCases()).rejects.toMatchObject({
      status: 403,
      code: "FORBIDDEN",
      message: "Reader access is required.",
    });
  });

  it("uses a safe fallback for a non-JSON error response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => response("<html>unexpected</html>", 500)));
    const request = createApiClient("memory-token").listCases();
    await expect(request).rejects.toBeInstanceOf(ApiError);
    await expect(request).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
  });

  it("validates the list envelope and returns only contract-shaped records", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => response({ items: [{
      case_id: "case-1",
      title: "Contract case",
      description: "Evidence is still required.",
      state: "NEEDS_EVIDENCE",
      reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
      created_by: "analyst.local",
      created_at: "2026-09-28T10:00:00Z",
      updated_at: "2026-09-28T10:00:00Z",
    }] })));
    await expect(createApiClient("memory-token").listCases()).resolves.toMatchObject({ items: [{ case_id: "case-1" }] });
  });

  it("creates UUID-shaped idempotency keys", () => {
    expect(createIdempotencyKey()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });
});
