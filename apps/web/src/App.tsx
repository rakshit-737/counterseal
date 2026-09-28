import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleDot,
  Clock3,
  FilePlus2,
  FolderKanban,
  Inbox,
  KeyRound,
  LogOut,
  Menu,
  Plus,
  RefreshCw,
  Search,
  ServerOff,
  ShieldCheck,
  TimerReset,
  UserRound,
  X,
} from "lucide-react";
import {
  QueryClient,
  QueryClientProvider,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  ApiError,
  createApiClient,
  type CaseCreateInput,
  type CaseRecord,
  type JobResponse,
  type MeResponse,
  type TimelineEvent,
} from "./lib/api";
import { actionLabel, canWrite, formatTimestamp, roleLabel, stateLabel } from "./lib/cases";

function apiError(error: unknown): ApiError | null {
  return error instanceof ApiError ? error : null;
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return "The request could not be completed. Try again.";
}

function App() {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: { retry: false },
          mutations: { retry: false },
        },
      }),
  );

  return (
    <QueryClientProvider client={queryClient}>
      <WorkspaceApp />
    </QueryClientProvider>
  );
}

function WorkspaceApp() {
  const queryClient = useQueryClient();
  const [token, setToken] = useState<string | null>(null);
  const [session, setSession] = useState<MeResponse | null>(null);
  const [authNotice, setAuthNotice] = useState<string | null>(null);
  const [tokenInput, setTokenInput] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [createInput, setCreateInput] = useState<CaseCreateInput>({ title: "", description: "" });
  const [investigationJob, setInvestigationJob] = useState<JobResponse | null>(null);

  const api = useMemo(() => (token ? createApiClient(token) : null), [token]);

  const loginQuery = useMutation<MeResponse, unknown, string>({
    mutationFn: (candidate) => createApiClient(candidate).me(),
    retry: false,
    onSuccess: (identity, candidate) => {
      queryClient.clear();
      setToken(candidate);
      setSession(identity);
      setAuthNotice(null);
      setTokenInput("");
      setSelectedId(null);
    },
  });

  const logout = (notice?: string) => {
    api?.dispose();
    queryClient.clear();
    setToken(null);
    setSession(null);
    setAuthNotice(notice ?? null);
    setTokenInput("");
    setSelectedId(null);
    setSearch("");
    setDialogOpen(false);
    setCreateInput({ title: "", description: "" });
    setInvestigationJob(null);
    loginQuery.reset();
  };

  const meQuery = useQuery<MeResponse, unknown>({
    queryKey: ["me"],
    queryFn: () => {
      if (!api) throw new Error("No authenticated client.");
      return api.me();
    },
    enabled: Boolean(api),
    retry: false,
  });
  const identity = meQuery.data ?? session;

  const casesQuery = useQuery<{ items: CaseRecord[] }, unknown>({
    queryKey: ["cases"],
    queryFn: () => {
      if (!api) throw new Error("No authenticated client.");
      return api.listCases();
    },
    enabled: Boolean(api && identity),
    retry: false,
  });

  const detailQuery = useQuery<CaseRecord, unknown>({
    queryKey: ["case", selectedId],
    queryFn: () => {
      if (!api || !selectedId) throw new Error("No case selected.");
      return api.getCase(selectedId);
    },
    enabled: Boolean(api && identity && selectedId),
    retry: false,
  });

  const timelineQuery = useQuery<{ items: TimelineEvent[] }, unknown>({
    queryKey: ["timeline", selectedId],
    queryFn: () => {
      if (!api || !selectedId) throw new Error("No case selected.");
      return api.getTimeline(selectedId);
    },
    enabled: Boolean(api && identity && selectedId),
    retry: false,
  });

  const createCase = useMutation<CaseRecord, unknown, CaseCreateInput>({
    mutationFn: (input) => {
      if (!api) throw new Error("No authenticated client.");
      return api.createCase(input);
    },
    retry: false,
    onSuccess: (created) => {
      queryClient.setQueryData(["case", created.case_id], created);
      queryClient.invalidateQueries({ queryKey: ["cases"] });
      setSelectedId(created.case_id);
      setDialogOpen(false);
      setCreateInput({ title: "", description: "" });
    },
  });

  const requestInvestigation = useMutation<JobResponse, unknown, string>({
    mutationFn: (caseId) => {
      if (!api) throw new Error("No authenticated client.");
      return api.requestInvestigation(caseId);
    },
    retry: false,
    onSuccess: (job) => {
      setInvestigationJob(job);
      queryClient.invalidateQueries({ queryKey: ["timeline", job.case_id] });
      queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
  });

  useEffect(() => {
    const failures = [meQuery.error, casesQuery.error, detailQuery.error, timelineQuery.error, createCase.error, requestInvestigation.error];
    if (token && failures.some((failure) => apiError(failure)?.status === 401)) {
      logout("The authenticated session expired or was revoked. Validate the token again.");
    }
    // The logout callback deliberately clears the in-memory client and every query cache.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, meQuery.error, casesQuery.error, detailQuery.error, timelineQuery.error, createCase.error, requestInvestigation.error]);

  if (!token) {
    return (
      <LoginScreen
        value={tokenInput}
        onChange={setTokenInput}
        onSubmit={(candidate) => { setAuthNotice(null); loginQuery.mutate(candidate); }}
        isPending={loginQuery.isPending}
        error={loginQuery.error}
        notice={authNotice}
      />
    );
  }

  if (meQuery.isPending && !identity) {
    return <LoadingScreen label="Validating the authenticated session" />;
  }

  if (meQuery.error && apiError(meQuery.error)?.status !== 401) {
    return (
      <SessionError
        error={meQuery.error}
        onRetry={() => void meQuery.refetch()}
        onLogout={logout}
      />
    );
  }

  if (!identity) {
    return <LoadingScreen label="Loading the authenticated session" />;
  }

  const records = casesQuery.data?.items ?? [];
  const normalizedSearch = search.trim().toLowerCase();
  const visibleCases = records.filter((record) =>
    normalizedSearch.length === 0 ||
    [record.case_id, record.title, record.description, record.created_by].some((value) =>
      value.toLowerCase().includes(normalizedSearch),
    ),
  );
  const selectedFromList = records.find((record) => record.case_id === selectedId) ?? null;
  const selectedCase = detailQuery.data ?? selectedFromList;
  const writable = canWrite(identity.role);

  return (
    <div className="app-shell">
      <aside className={`side-rail ${menuOpen ? "is-open" : ""}`}>
        <div className="rail-topline">
          <button className="brand brand-button" type="button" aria-label="Counterseal case register" onClick={() => { setSelectedId(null); setMenuOpen(false); }}>
            <span className="brand-mark" aria-hidden="true"><ShieldCheck size={18} strokeWidth={2.5} /></span>
            <span>counterseal</span>
          </button>
          <button className="icon-button rail-close" type="button" aria-label="Close navigation" onClick={() => setMenuOpen(false)}>
            <X size={17} aria-hidden="true" />
          </button>
        </div>

        <div className="rail-label">Control plane</div>
        <nav className="primary-nav" aria-label="Primary navigation">
          <button className="nav-item is-active" type="button" aria-current="page" onClick={() => { setSelectedId(null); setMenuOpen(false); }}>
            <FolderKanban size={17} aria-hidden="true" />
            <span>Case register</span>
          </button>
          <button className="nav-item" type="button" disabled>
            <CircleDot size={17} aria-hidden="true" />
            <span>Evidence</span>
            <span className="nav-soon">Phase 2</span>
          </button>
          <button className="nav-item" type="button" disabled>
            <ServerOff size={17} aria-hidden="true" />
            <span>Security engine</span>
            <span className="nav-soon">Unavailable</span>
          </button>
        </nav>

        <div className="rail-spacer" />
        <div className="rail-label">Session</div>
        <div className="session-card">
          <div className="session-avatar" aria-hidden="true">{identity.subject.slice(0, 1).toUpperCase()}</div>
          <div className="session-copy">
            <strong title={identity.subject}>{identity.subject}</strong>
            <span>{roleLabel(identity.role)} role</span>
          </div>
          <button className="icon-button session-logout" type="button" aria-label="Sign out" onClick={() => logout()}>
            <LogOut size={15} aria-hidden="true" />
          </button>
        </div>
      </aside>

      {menuOpen && <button className="rail-scrim" type="button" aria-label="Close navigation" onClick={() => setMenuOpen(false)} />}

      <main className="main-canvas" id="cases">
        <header className="page-header">
          <div className="header-copy">
            <div className="breadcrumb"><span>Control plane</span><ChevronRight size={13} aria-hidden="true" /><strong>Case register</strong></div>
            <h1>Case register</h1>
            <p>Read the current control-plane record before requesting any investigation transport.</p>
          </div>
          <div className="header-actions">
            <button className="icon-button mobile-menu" type="button" aria-label="Open navigation" onClick={() => setMenuOpen(true)}>
              <Menu size={19} aria-hidden="true" />
            </button>
            <span className="role-chip"><UserRound size={14} aria-hidden="true" /> {roleLabel(identity.role)}</span>
            <button className="button button-primary" type="button" onClick={() => setDialogOpen(true)} disabled={!writable} title={!writable ? "Your role is read-only" : undefined}>
              <Plus size={17} aria-hidden="true" />
              New case
            </button>
          </div>
        </header>

        <section className="phase-notice" aria-label="Phase 1 boundary notice">
          <div className="notice-icon"><KeyRound size={18} aria-hidden="true" /></div>
          <div>
            <strong>FIXTURE-VALIDATED—NOT PRODUCTION ASSURANCE</strong>
            <p>These records come from the authenticated same-origin API. Cases remain <code>NEEDS_EVIDENCE</code> because <code>SECURITY_ENGINE_NOT_IMPLEMENTED</code>.</p>
          </div>
        </section>

        <div className="content-grid">
          <section className="queue-panel" aria-labelledby="queue-heading">
            <div className="panel-heading">
              <div>
                <h2 id="queue-heading">Cases</h2>
                <span className="panel-meta">Returned by <code>/v1/cases</code></span>
              </div>
              <button className="icon-button" type="button" aria-label="Refresh cases" onClick={() => void casesQuery.refetch()} disabled={casesQuery.isFetching}>
                <RefreshCw size={16} aria-hidden="true" className={casesQuery.isFetching ? "spin" : undefined} />
              </button>
            </div>

            <div className="queue-tools">
              <label className="search-field">
                <Search size={16} aria-hidden="true" />
                <span className="sr-only">Search cases</span>
                <input type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search title, description, or creator" />
              </label>
            </div>

            {casesQuery.isPending ? (
              <CaseListSkeleton />
            ) : casesQuery.error ? (
              <ErrorState title="Cases could not be loaded" error={casesQuery.error} onRetry={() => void casesQuery.refetch()} />
            ) : visibleCases.length > 0 ? (
              <ul className="case-list">
                {visibleCases.map((record) => (
                  <CaseRow key={record.case_id} record={record} selected={record.case_id === selectedId} onSelect={() => { setSelectedId(record.case_id); setInvestigationJob(null); }} />
                ))}
              </ul>
            ) : (
              <EmptyCases hasSearch={Boolean(normalizedSearch)} writable={writable} onClear={() => setSearch("")} onCreate={() => setDialogOpen(true)} />
            )}
          </section>

          <CaseDetail
            record={selectedCase}
            detailLoading={Boolean(selectedId && detailQuery.isPending)}
            detailError={detailQuery.error}
            onRetryDetail={() => void detailQuery.refetch()}
            onClear={() => setSelectedId(null)}
            timeline={timelineQuery.data?.items ?? []}
            timelineLoading={Boolean(selectedId && timelineQuery.isPending)}
            timelineError={timelineQuery.error}
            onRetryTimeline={() => void timelineQuery.refetch()}
            writable={writable}
            investigationJob={investigationJob}
            investigationPending={requestInvestigation.isPending}
            investigationError={requestInvestigation.error}
            onInvestigate={() => selectedId && requestInvestigation.mutate(selectedId)}
          />
        </div>

        <footer className="boundary-note">
          <div className="boundary-icon"><TimerReset size={16} aria-hidden="true" /></div>
          <div>
            <strong>Transport is the current boundary.</strong>
            <p>Queue responses are metadata only. No security engine runs in this phase, and this workspace does not assert investigation results, approvals, or assurance.</p>
          </div>
          <span className="api-note">/v1/me · /v1/cases</span>
        </footer>
      </main>

      <CreateCaseDialog
        open={dialogOpen}
        value={createInput}
        isPending={createCase.isPending}
        error={createCase.error}
        onChange={setCreateInput}
        onClose={() => { if (!createCase.isPending) { setDialogOpen(false); createCase.reset(); } }}
        onSubmit={(input) => createCase.mutate(input)}
      />
    </div>
  );
}

function LoginScreen({
  value,
  onChange,
  onSubmit,
  isPending,
  error,
  notice,
}: {
  value: string;
  onChange: (value: string) => void;
  onSubmit: (value: string) => void;
  isPending: boolean;
  error: unknown;
  notice: string | null;
}) {
  const [validationError, setValidationError] = useState<string | null>(null);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const candidate = value.trim();
    if (!candidate) {
      setValidationError("Enter a bearer token to validate the session.");
      return;
    }
    setValidationError(null);
    onSubmit(candidate);
  };

  return (
    <main className="login-shell">
      <section className="login-card" aria-labelledby="login-heading">
        <div className="login-brand"><span className="brand-mark" aria-hidden="true"><ShieldCheck size={19} strokeWidth={2.5} /></span><strong>counterseal</strong></div>
        <div className="login-rule" aria-hidden="true" />
        <h1 id="login-heading">Sign in to the case register</h1>
        <p className="login-lede">Validate a local-development bearer token with the control plane before reading case records.</p>
        <form className="login-form" onSubmit={submit}>
          <label htmlFor="bearer-token">Local bearer token</label>
          <input
            id="bearer-token"
            name="bearer-token"
            type="password"
            autoComplete="off"
            value={value}
            onChange={(event) => onChange(event.target.value)}
            aria-describedby="token-help token-error"
            spellCheck={false}
            autoFocus
          />
          <p id="token-help" className="field-help">Held in memory for this tab only. It is never written to browser storage or a URL.</p>
          {notice && <p className="auth-notice" role="status">{notice}</p>}
          {(validationError || error) ? <p id="token-error" className="form-error" role="alert">{validationError ?? errorMessage(error)}</p> : null}
          <button className="button button-primary login-submit" type="submit" disabled={isPending}>
            {isPending ? "Validating…" : "Validate token"}
            {!isPending && <ArrowUpRight size={16} aria-hidden="true" />}
          </button>
        </form>
        <p className="login-boundary"><span>Phase 1 control plane</span> · FIXTURE-VALIDATED—NOT PRODUCTION ASSURANCE</p>
      </section>
    </main>
  );
}

function LoadingScreen({ label }: { label: string }) {
  return (
    <main className="status-shell" aria-busy="true">
      <div className="status-mark"><RefreshCw size={20} aria-hidden="true" className="spin" /></div>
      <h1>{label}</h1>
      <p>The control plane is validating the current session.</p>
    </main>
  );
}

function SessionError({ error, onRetry, onLogout }: { error: unknown; onRetry: () => void; onLogout: () => void }) {
  return (
    <main className="status-shell">
      <div className="status-mark status-mark-error"><AlertTriangle size={20} aria-hidden="true" /></div>
      <h1>Session check unavailable</h1>
      <p>{errorMessage(error)}</p>
      <div className="status-actions"><button className="button button-primary" type="button" onClick={onRetry}>Try again</button><button className="button button-secondary" type="button" onClick={onLogout}>Sign out</button></div>
    </main>
  );
}

function CaseListSkeleton() {
  return (
    <div className="skeleton-list" aria-label="Loading cases" aria-busy="true">
      {["one", "two", "three"].map((key) => <div className="skeleton-row" key={key}><span /><div><b /><i /></div><em /></div>)}
    </div>
  );
}

function ErrorState({ title, error, onRetry }: { title: string; error: unknown; onRetry: () => void }) {
  const known = apiError(error);
  return (
    <div className="inline-state error-state" role="alert">
      <div className="state-icon"><AlertTriangle size={19} aria-hidden="true" /></div>
      <h3>{title}</h3>
      <p>{errorMessage(error)}</p>
      {known && <code>{known.code}</code>}
      <button className="button button-secondary" type="button" onClick={onRetry}><RefreshCw size={15} aria-hidden="true" /> Try again</button>
    </div>
  );
}

function EmptyCases({ hasSearch, writable, onClear, onCreate }: { hasSearch: boolean; writable: boolean; onClear: () => void; onCreate: () => void }) {
  return (
    <div className="inline-state empty-state" role="status">
      <div className="state-icon"><Inbox size={20} aria-hidden="true" /></div>
      <h3>{hasSearch ? "No cases match this search" : "No cases recorded"}</h3>
      <p>{hasSearch ? "Clear the search to review the full API-backed register." : "Create a case to establish a control-plane record. No investigation result is implied."}</p>
      {hasSearch ? <button className="button button-secondary" type="button" onClick={onClear}>Clear search</button> : writable ? <button className="button button-primary" type="button" onClick={onCreate}><FilePlus2 size={15} aria-hidden="true" /> New case</button> : <span className="read-only-note">Your role can read records but cannot create them.</span>}
    </div>
  );
}

function CaseRow({ record, selected, onSelect }: { record: CaseRecord; selected: boolean; onSelect: () => void }) {
  return (
    <li>
      <button className={`case-row ${selected ? "is-selected" : ""}`} type="button" aria-current={selected ? "true" : undefined} onClick={onSelect}>
        <span className="case-status-dot" aria-hidden="true" />
        <span className="case-row-main">
          <span className="case-row-title"><strong>{record.title}</strong><code>{record.case_id}</code></span>
          <span className="case-row-description">{record.description || "No description provided."}</span>
        </span>
        <span className="status-pill">{stateLabel(record.state)}</span>
        <span className="case-row-owner">{record.created_by}</span>
        <span className="case-row-time">{formatTimestamp(record.updated_at)}</span>
        <ChevronRight className="case-row-chevron" size={17} aria-hidden="true" />
      </button>
    </li>
  );
}

function CaseDetail({
  record,
  detailLoading,
  detailError,
  onRetryDetail,
  onClear,
  timeline,
  timelineLoading,
  timelineError,
  onRetryTimeline,
  writable,
  investigationJob,
  investigationPending,
  investigationError,
  onInvestigate,
}: {
  record: CaseRecord | null;
  detailLoading: boolean;
  detailError: unknown;
  onRetryDetail: () => void;
  onClear: () => void;
  timeline: TimelineEvent[];
  timelineLoading: boolean;
  timelineError: unknown;
  onRetryTimeline: () => void;
  writable: boolean;
  investigationJob: JobResponse | null;
  investigationPending: boolean;
  investigationError: unknown;
  onInvestigate: () => void;
}) {
  if (!record && !detailLoading && !detailError) {
    return <aside className="detail-panel detail-empty" aria-label="Case details empty state"><div className="empty-illustration" aria-hidden="true"><span /><span /><span /></div><h2>Select a case</h2><p>Choose a record from the register to inspect its API fields and append-only metadata timeline.</p><div className="empty-rule"><span>CASE DETAIL</span></div><small>No approval, assurance, or investigation outcome is shown here.</small></aside>;
  }

  if (detailLoading && !record) {
    return <aside className="detail-panel detail-loading" aria-busy="true"><RefreshCw size={19} aria-hidden="true" className="spin" /><h2>Loading case detail</h2><p>Reading the selected record from the control plane.</p></aside>;
  }

  if (detailError && !record) {
    return <aside className="detail-panel"><ErrorState title="Case detail unavailable" error={detailError} onRetry={onRetryDetail} /></aside>;
  }

  if (!record) return null;

  return (
    <aside className="detail-panel" aria-label={`Details for ${record.title}`}>
      <div className="detail-header">
        <div>
          <span className="detail-label">Case record</span>
          <h2>{record.title}</h2>
          <code className="detail-id">{record.case_id}</code>
        </div>
        <button className="icon-button" type="button" aria-label="Clear selected case" onClick={onClear}><X size={16} aria-hidden="true" /></button>
      </div>

      <div className="detail-status-line"><span className="status-pill">{stateLabel(record.state)}</span><code>{record.reason}</code></div>
      <p className="detail-description">{record.description || "No description provided."}</p>

      <dl className="detail-facts">
        <div><dt>Created by</dt><dd>{record.created_by}</dd></div>
        <div><dt>Created</dt><dd>{formatTimestamp(record.created_at)}</dd></div>
        <div><dt>Updated</dt><dd>{formatTimestamp(record.updated_at)}</dd></div>
        <div><dt>Record state</dt><dd><code>{record.state}</code></dd></div>
      </dl>

      <InvestigationPanel
        writable={writable}
        job={investigationJob}
        pending={investigationPending}
        error={investigationError}
        onRequest={onInvestigate}
      />

      <section className="timeline-section" aria-labelledby="timeline-heading">
        <div className="section-heading"><div><h3 id="timeline-heading">Metadata timeline</h3><span>Returned by <code>/timeline</code></span></div><Clock3 size={15} aria-hidden="true" /></div>
        {timelineLoading ? <div className="timeline-loading" aria-busy="true"><span /><span /></div> : timelineError ? <ErrorState title="Timeline unavailable" error={timelineError} onRetry={onRetryTimeline} /> : timeline.length > 0 ? <ol className="timeline-list">{timeline.map((event) => <TimelineRow event={event} key={event.event_id} />)}</ol> : <p className="timeline-empty">No metadata events were returned for this case.</p>}
      </section>
    </aside>
  );
}

function InvestigationPanel({ writable, job, pending, error, onRequest }: { writable: boolean; job: JobResponse | null; pending: boolean; error: unknown; onRequest: () => void }) {
  return (
    <section className="investigation-panel" aria-labelledby="investigation-heading">
      <div className="section-heading"><div><h3 id="investigation-heading">Investigation transport</h3><span>Queue request only</span></div><ServerOff size={15} aria-hidden="true" /></div>
      <p>No security engine runs in Phase 1. A successful request is a queue transport acknowledgement, never an investigation result.</p>
      {job ? (
        <div className="job-result" role="status"><div className="job-result-head"><Check size={14} aria-hidden="true" /><strong>Queue transport accepted</strong></div><dl><div><dt>Job</dt><dd><code>{job.job_id}</code></dd></div><div><dt>Status</dt><dd>{job.status}</dd></div><div><dt>Reason</dt><dd><code>{job.reason}</code></dd></div></dl></div>
      ) : writable ? (
        <button className="button button-secondary" type="button" onClick={onRequest} disabled={pending}>{pending ? "Queueing request…" : "Queue investigation request"}<ArrowUpRight size={15} aria-hidden="true" /></button>
      ) : <p className="read-only-note">Your role can read this record but cannot request queue transport.</p>}
      {error ? <p className="form-error" role="alert">{errorMessage(error)} {apiError(error) ? <code>{apiError(error)?.code}</code> : null}</p> : null}
    </section>
  );
}

function TimelineRow({ event }: { event: TimelineEvent }) {
  return (
    <li className="timeline-row">
      <span className="timeline-marker" aria-hidden="true" />
      <div className="timeline-content"><div className="timeline-row-head"><strong>{actionLabel(event.action)}</strong><time dateTime={event.occurred_at}>{formatTimestamp(event.occurred_at)}</time></div><span>Actor: {event.actor}</span>{Object.keys(event.details).length > 0 && <p>{Object.entries(event.details).map(([key, value]) => `${key}: ${String(value)}`).join(" · ")}</p>}</div>
    </li>
  );
}

function CreateCaseDialog({ open, value, isPending, error, onChange, onClose, onSubmit }: { open: boolean; value: CaseCreateInput; isPending: boolean; error: unknown; onChange: (value: CaseCreateInput) => void; onClose: () => void; onSubmit: (value: CaseCreateInput) => void }) {
  const titleRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const openerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return undefined;
    openerRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    titleRef.current?.focus();
    return () => openerRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !dialogRef.current) return;
      const focusable = Array.from(dialogRef.current.querySelectorAll<HTMLElement>("button, input, textarea"))
        .filter((element) => !element.hasAttribute("disabled"));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    onSubmit({ title: value.title.trim(), description: value.description.trim() });
  };

  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) onClose(); }}>
      <div className="local-dialog" ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="create-case-heading" aria-describedby="create-case-help">
        <div className="dialog-header"><div className="dialog-icon"><FilePlus2 size={19} aria-hidden="true" /></div><button className="icon-button" type="button" aria-label="Close new case dialog" onClick={onClose}><X size={16} aria-hidden="true" /></button></div>
        <h2 id="create-case-heading">Create a case record</h2>
        <p id="create-case-help">This writes a case with <code>NEEDS_EVIDENCE</code>. It does not run an investigation or establish assurance.</p>
        <form className="case-form" onSubmit={submit}>
          <label htmlFor="case-title">Title</label>
          <input ref={titleRef} id="case-title" name="title" maxLength={256} required value={value.title} onChange={(event) => onChange({ ...value, title: event.target.value })} />
          <label htmlFor="case-description">Description <span>(optional)</span></label>
          <textarea id="case-description" name="description" maxLength={8192} rows={4} value={value.description} onChange={(event) => onChange({ ...value, description: event.target.value })} />
          {error ? <p className="form-error" role="alert">{errorMessage(error)} {apiError(error) ? <code>{apiError(error)?.code}</code> : null}</p> : null}
          <div className="dialog-actions"><button className="button button-secondary" type="button" onClick={onClose} disabled={isPending}>Cancel</button><button className="button button-primary" type="submit" disabled={isPending}>{isPending ? "Creating…" : "Create case"}</button></div>
        </form>
      </div>
    </div>
  );
}

export { App };
export default App;
