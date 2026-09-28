import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import type { MeResponse } from "./lib/api";

type FetchCall = { path: string; init?: RequestInit };

const identity: MeResponse = { subject: "analyst.local", role: "analyst" };

function response(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  } as Response;
}

function renderApp() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}><App /></QueryClientProvider>);
}

function routeApi({
  me = identity,
  cases = [],
  casesStatus = 200,
  createStatus = 201,
  onCreate,
}: {
  me?: MeResponse;
  cases?: unknown[];
  casesStatus?: number;
  createStatus?: number;
  onCreate?: (body: unknown) => unknown;
} = {}) {
  const calls: FetchCall[] = [];
  let latestCreated: unknown;
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    calls.push({ path, init });
    if (path === "/v1/me") return response(me);
    if (path === "/v1/cases" && (!init || init.method === undefined)) return response({ items: cases }, casesStatus);
    if (path === "/v1/cases" && init?.method === "POST") {
      const body = JSON.parse(String(init.body));
      const created = onCreate?.(body) ?? {
        case_id: "case-created",
        title: body.title,
        description: body.description,
        state: "NEEDS_EVIDENCE",
        reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
        created_by: me.subject,
        created_at: "2026-09-28T10:00:00Z",
        updated_at: "2026-09-28T10:00:00Z",
      };
      latestCreated = created;
      return response(created, createStatus);
    }
    if (path.endsWith("/investigations")) {
      return response({
        job_id: "job-1",
        case_id: path.split("/")[3],
        kind: "INVESTIGATION",
        status: "QUEUED",
        reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
        requested_by: me.subject,
        created_at: "2026-09-28T10:01:00Z",
        updated_at: "2026-09-28T10:01:00Z",
        attempts: 0,
        lease_expires_at: null,
        completed_at: null,
        outcome: null,
      }, 202);
    }
    if (path.includes("/timeline")) return response({ items: [] });
    if (path.startsWith("/v1/cases/")) {
      return response(latestCreated ?? cases[0] ?? {
        case_id: "case-created",
        title: "Created case",
        description: "Created from the UI.",
        state: "NEEDS_EVIDENCE",
        reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
        created_by: me.subject,
        created_at: "2026-09-28T10:00:00Z",
        updated_at: "2026-09-28T10:00:00Z",
      });
    }
    return response({ error: { code: "NOT_FOUND", message: "Route not mocked." } }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("authenticated case register", () => {
  it("validates a bearer token with /v1/me and never persists it in browser storage", async () => {
    const { calls } = routeApi();
    const storageWrite = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    renderApp();

    await user.type(screen.getByLabelText("Local bearer token"), "token-only-in-memory");
    await user.click(screen.getByRole("button", { name: "Validate token" }));
    expect(await screen.findByRole("heading", { name: "Case register" })).toBeInTheDocument();

    const meCall = calls.find((call) => call.path === "/v1/me");
    expect(meCall).toBeDefined();
    expect(new Headers(meCall?.init?.headers).get("Authorization")).toBe("Bearer token-only-in-memory");
    expect(storageWrite).not.toHaveBeenCalled();
  });

  it("shows a clear authorization state for a token without case access", async () => {
    routeApi({
      me: { subject: "viewer.local", role: "viewer" },
      casesStatus: 403,
    });
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText("Local bearer token"), "viewer-token");
    await user.click(screen.getByRole("button", { name: "Validate token" }));

    expect(await screen.findByText("Your role is not permitted to perform this action.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });

  it("clears the session on 401 and requires token validation again", async () => {
    let meRequests = 0;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === "/v1/me") {
        meRequests += 1;
        if (meRequests === 1) return response(identity);
        return response({ error: { code: "UNAUTHENTICATED", message: "A valid bearer token is required." } }, 401);
      }
      return response({ items: [] });
    }));
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText("Local bearer token"), "expired-token");
    await user.click(screen.getByRole("button", { name: "Validate token" }));

    expect(await screen.findByText("The authenticated session expired or was revoked. Validate the token again.")).toBeInTheDocument();
    expect(screen.getByLabelText("Local bearer token")).toHaveValue("");
  });

  it("signing out clears visible case data and returns to an empty token form", async () => {
    routeApi({ cases: [] });
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText("Local bearer token"), "analyst-token");
    await user.click(screen.getByRole("button", { name: "Validate token" }));
    await screen.findByText("No cases recorded");
    await user.click(screen.getByRole("button", { name: "Sign out" }));

    expect(screen.getByRole("heading", { name: "Sign in to the case register" })).toBeInTheDocument();
    expect(screen.getByLabelText("Local bearer token")).toHaveValue("");
    expect(screen.queryByText("No cases recorded")).not.toBeInTheDocument();
  });

  it("renders the real empty register state without fixture rows", async () => {
    routeApi({ cases: [] });
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText("Local bearer token"), "analyst-token");
    await user.click(screen.getByRole("button", { name: "Validate token" }));

    expect(await screen.findByText("No cases recorded")).toBeInTheDocument();
  });

  it("creates a case with the API body and opens the returned record", async () => {
    let created: any;
    const { calls } = routeApi({
      cases: [],
      onCreate: (body) => {
        const input = body as { title: string; description: string };
        created = {
          case_id: "case-created",
          title: input.title,
          description: input.description,
          state: "NEEDS_EVIDENCE",
          reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
          created_by: identity.subject,
          created_at: "2026-09-28T10:00:00Z",
          updated_at: "2026-09-28T10:00:00Z",
        };
        return created;
      },
    });
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText("Local bearer token"), "analyst-token");
    await user.click(screen.getByRole("button", { name: "Validate token" }));
    await screen.findByText("No cases recorded");
    await user.click(screen.getAllByRole("button", { name: "New case" })[0]);
    await user.type(screen.getByLabelText("Title"), "API-backed case");
    const descriptionField = screen.getByRole("textbox", { name: "Description (optional)" });
    await user.type(descriptionField, "A real control-plane record.");
    await user.click(screen.getByRole("button", { name: "Create case" }));

    await waitFor(() => expect(document.body.textContent).toContain("API-backed case"));
    const createCall = calls.find((call) => call.path === "/v1/cases" && call.init?.method === "POST");
    expect(JSON.parse(String(createCall?.init?.body))).toEqual({ title: "API-backed case", description: "A real control-plane record." });
    expect(created.state).toBe("NEEDS_EVIDENCE");
  });

  it("keeps API failures safe and recoverable", async () => {
    routeApi({ createStatus: 500, onCreate: () => ({ error: { code: "DATABASE_UNAVAILABLE", message: "Database is unavailable." } }) });
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText("Local bearer token"), "analyst-token");
    await user.click(screen.getByRole("button", { name: "Validate token" }));
    await screen.findByText("No cases recorded");
    await user.click(screen.getAllByRole("button", { name: "New case" })[0]);
    await user.type(screen.getByLabelText("Title"), "Will fail");
    await user.click(screen.getByRole("button", { name: "Create case" }));

    expect(await screen.findByText("Database is unavailable.")).toBeInTheDocument();
    expect(screen.getByText("DATABASE_UNAVAILABLE")).toBeInTheDocument();
  });

  it("sends a UUID idempotency key and labels investigation as queue transport only", async () => {
    const record = {
      case_id: "case-1",
      title: "Queue boundary",
      description: "No engine result.",
      state: "NEEDS_EVIDENCE",
      reason: "SECURITY_ENGINE_NOT_IMPLEMENTED",
      created_by: identity.subject,
      created_at: "2026-09-28T10:00:00Z",
      updated_at: "2026-09-28T10:00:00Z",
    } as const;
    const { calls } = routeApi({ cases: [record] });
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText("Local bearer token"), "analyst-token");
    await user.click(screen.getByRole("button", { name: "Validate token" }));
    await user.click(await screen.findByRole("button", { name: /Queue boundary/ }));
    await screen.findByText("Queue investigation request");

    await user.click(screen.getByRole("button", { name: "Queue investigation request" }));
    await waitFor(() => expect(screen.getByText("Queue transport accepted")).toBeInTheDocument());
    const investigation = calls.find((call) => call.path.endsWith("/investigations"));
    const key = new Headers(investigation?.init?.headers).get("Idempotency-Key");
    expect(key).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    expect(screen.getByText(/No security engine runs in Phase 1/)).toBeInTheDocument();
  });
});
