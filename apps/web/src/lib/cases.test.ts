import { describe, expect, it } from "vitest";
import { actionLabel, canWrite, formatTimestamp, roleLabel, stateLabel } from "./cases";

describe("case vocabulary", () => {
  it("keeps the API state and audit labels readable", () => {
    expect(stateLabel("NEEDS_EVIDENCE")).toBe("NEEDS EVIDENCE");
    expect(actionLabel("CASE_CREATED")).toBe("CASE CREATED");
  });

  it("only treats human write roles as write-capable", () => {
    expect(canWrite("viewer")).toBe(false);
    expect(canWrite("worker")).toBe(false);
    expect(canWrite("analyst")).toBe(true);
    expect(canWrite("admin")).toBe(true);
    expect(roleLabel("approver")).toBe("Approver");
  });

  it("falls back safely when a timestamp is not parseable", () => {
    expect(formatTimestamp("not-a-date")).toBe("not-a-date");
  });
});
