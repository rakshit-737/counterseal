import type { CaseRecord, MeResponse, TimelineEvent } from "./api";

export type { CaseRecord, MeResponse, TimelineEvent };

export function roleLabel(role: MeResponse["role"]): string {
  return role[0].toUpperCase() + role.slice(1);
}

export function stateLabel(state: CaseRecord["state"]): string {
  return state.replaceAll("_", " ");
}

export function actionLabel(action: TimelineEvent["action"]): string {
  return action.replaceAll("_", " ");
}

export function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function canWrite(role: MeResponse["role"]): boolean {
  return role === "analyst" || role === "approver" || role === "admin";
}
