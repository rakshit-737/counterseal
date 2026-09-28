/** Same-origin API client for the authenticated Counterseal control plane. */

export type HealthEndpoint = "/healthz" | "/readyz";

export type HealthResponse = {
  status: string;
  detail?: string;
};

export type ApiErrorBody = {
  error: {
    code: string;
    message: string;
  };
};

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export type MeResponse = {
  subject: string;
  role: "viewer" | "analyst" | "approver" | "admin" | "worker";
};

export type CaseState = "NEEDS_EVIDENCE";

export type CaseRecord = {
  case_id: string;
  title: string;
  description: string;
  state: CaseState;
  reason: "SECURITY_ENGINE_NOT_IMPLEMENTED";
  created_by: string;
  created_at: string;
  updated_at: string;
};

export type CaseList = {
  items: CaseRecord[];
};

export type TimelineEvent = {
  sequence: number;
  event_id: string;
  case_id: string;
  actor: string;
  action: string;
  occurred_at: string;
  details: Record<string, string | number>;
};

export type TimelineResponse = {
  items: TimelineEvent[];
};

export type JobResponse = {
  job_id: string;
  case_id: string;
  kind: "INVESTIGATION";
  status: "QUEUED" | "LEASED" | "COMPLETED";
  reason: "SECURITY_ENGINE_NOT_IMPLEMENTED";
  requested_by: string;
  created_at: string;
  updated_at: string;
  attempts: number;
  lease_expires_at: string | null;
  completed_at: string | null;
  outcome: "UNSUPPORTED" | null;
};

export type CaseCreateInput = {
  title: string;
  description: string;
};

export type HealthClient = {
  get(endpoint: HealthEndpoint, init?: RequestInit): Promise<Response>;
};

function isApiErrorBody(value: unknown): value is ApiErrorBody {
  if (!value || typeof value !== "object" || !("error" in value)) return false;
  const error = (value as { error?: unknown }).error;
  return Boolean(
    error &&
      typeof error === "object" &&
      typeof (error as { code?: unknown }).code === "string" &&
      typeof (error as { message?: unknown }).message === "string",
  );
}

function statusMessage(status: number): string {
  if (status === 401) return "Your session is not authenticated.";
  if (status === 403) return "Your role is not permitted to perform this action.";
  if (status === 404) return "The requested record was not found.";
  if (status === 422) return "The request could not be validated.";
  if (status >= 500) return "The control plane is unavailable. Try again.";
  return "The request could not be completed.";
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ApiError(response.status, "INVALID_RESPONSE", "The server returned an invalid response.");
  }
}

async function requestJson<T>(path: string, token: string | undefined, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body) headers.set("Content-Type", "application/json");

  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers,
    });
  } catch {
    if (init.signal?.aborted) throw new ApiError(0, "REQUEST_CANCELLED", "The request was cancelled.");
    throw new ApiError(0, "NETWORK_ERROR", "The control plane could not be reached.");
  }

  const payload = await readJson(response);
  if (!response.ok) {
    if (isApiErrorBody(payload)) {
      throw new ApiError(response.status, payload.error.code, payload.error.message);
    }
    throw new ApiError(response.status, `HTTP_${response.status}`, statusMessage(response.status));
  }
  return payload as T;
}

export function createHealthClient(baseUrl = ""): HealthClient {
  return {
    get(endpoint, init) {
      return fetch(`${baseUrl}${endpoint}`, {
        ...init,
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          ...init?.headers,
        },
      });
    },
  };
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function strings(value: Record<string, unknown>, fields: string[]) {
  return fields.every((field) => typeof value[field] === "string");
}

function isCase(value: unknown): value is CaseRecord {
  return object(value) &&
    strings(value, ["case_id", "title", "description", "created_by", "created_at", "updated_at"]) &&
    value.state === "NEEDS_EVIDENCE" && value.reason === "SECURITY_ENGINE_NOT_IMPLEMENTED";
}

function isMe(value: unknown): value is MeResponse {
  return object(value) && typeof value.subject === "string" &&
    ["viewer", "analyst", "approver", "admin", "worker"].includes(String(value.role));
}

function isTimelineEvent(value: unknown): value is TimelineEvent {
  return object(value) && Number.isSafeInteger(value.sequence) &&
    strings(value, ["event_id", "case_id", "actor", "action", "occurred_at"]) &&
    object(value.details) && Object.values(value.details).every((item) =>
      typeof item === "string" || (typeof item === "number" && Number.isFinite(item)));
}

function isJob(value: unknown): value is JobResponse {
  return object(value) &&
    strings(value, ["job_id", "case_id", "requested_by", "created_at", "updated_at"]) &&
    value.kind === "INVESTIGATION" && value.reason === "SECURITY_ENGINE_NOT_IMPLEMENTED" &&
    ["QUEUED", "LEASED", "COMPLETED"].includes(String(value.status)) &&
    Number.isSafeInteger(value.attempts) && Number(value.attempts) >= 0 &&
    (value.lease_expires_at === null || typeof value.lease_expires_at === "string") &&
    (value.status === "COMPLETED"
      ? value.outcome === "UNSUPPORTED" && typeof value.completed_at === "string"
      : value.outcome === null && value.completed_at === null);
}

function validate<T>(value: unknown, predicate: (value: unknown) => value is T): T {
  if (!predicate(value)) {
    throw new ApiError(0, "INVALID_RESPONSE", "The server response did not match the Phase 1 contract. Refresh to try again.");
  }
  return value;
}

function items<T>(value: unknown, predicate: (value: unknown) => value is T): { items: T[] } {
  if (!object(value) || !Array.isArray(value.items)) {
    throw new ApiError(0, "INVALID_RESPONSE", "The server response did not contain a valid record list.");
  }
  return { items: value.items.map((item) => validate(item, predicate)) };
}

export function createApiClient(token: string) {
  let bearer: string | undefined = token;
  const controller = new AbortController();
  const request = <T>(path: string, init?: RequestInit) => {
    if (controller.signal.aborted) return Promise.reject(new ApiError(0, "REQUEST_CANCELLED", "The session has ended."));
    return requestJson<T>(path, bearer, { ...init, signal: controller.signal });
  };
  return {
    isActive: () => !controller.signal.aborted,
    dispose: () => { bearer = undefined; controller.abort(); },
    me: async () => validate(await request<unknown>("/v1/me"), isMe),
    listCases: async () => items(await request<unknown>("/v1/cases"), isCase),
    getCase: async (caseId: string) => validate(await request<unknown>(`/v1/cases/${encodeURIComponent(caseId)}`), isCase),
    getTimeline: async (caseId: string) => items(await request<unknown>(`/v1/cases/${encodeURIComponent(caseId)}/timeline`), isTimelineEvent),
    createCase: async (input: CaseCreateInput) =>
      validate(await request<unknown>("/v1/cases", {
        method: "POST",
        body: JSON.stringify(input),
      }), isCase),
    requestInvestigation: async (caseId: string) =>
      validate(await request<unknown>(`/v1/cases/${encodeURIComponent(caseId)}/investigations`, {
        method: "POST",
        headers: {
          "Idempotency-Key": createIdempotencyKey(),
        },
      }), isJob),
  };
}

export function createIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  const bytes = new Uint8Array(16);
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    throw new ApiError(0, "CRYPTO_UNAVAILABLE", "A secure context is required to create a request key. Use the loopback development URL.");
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
