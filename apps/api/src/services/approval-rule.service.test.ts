// Unit test: condition evaluation only (integration lives in approval.service.test.ts).
import { describe, expect, it } from "vitest";
import { conditionMatches } from "./approval-rule.service.js";

const APP = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const candidate = { applicationId: APP, taskId: "refund-42", scopeCount: 2 };

describe("conditionMatches", () => {
  it("empty condition matches anything", () => {
    expect(conditionMatches({}, candidate)).toBe(true);
    expect(conditionMatches({}, { ...candidate, taskId: null })).toBe(true);
  });

  it("application_ids filters by application", () => {
    expect(conditionMatches({ application_ids: [OTHER, APP] }, candidate)).toBe(true);
    expect(conditionMatches({ application_ids: [OTHER] }, candidate)).toBe(false);
  });

  it("task_id_prefix matches only the prefix", () => {
    expect(conditionMatches({ task_id_prefix: "refund-" }, candidate)).toBe(true);
    expect(conditionMatches({ task_id_prefix: "42" }, candidate)).toBe(false);
  });

  it("a null task_id never matches a task_id_prefix rule", () => {
    expect(conditionMatches({ task_id_prefix: "refund-" }, { ...candidate, taskId: null })).toBe(
      false,
    );
  });

  it("max_scopes rejects a wider request", () => {
    expect(conditionMatches({ max_scopes: 2 }, candidate)).toBe(true);
    expect(conditionMatches({ max_scopes: 1 }, candidate)).toBe(false);
  });

  it("all keys are ANDed", () => {
    const all = { application_ids: [APP], task_id_prefix: "refund-", max_scopes: 2 };
    expect(conditionMatches(all, candidate)).toBe(true);
    expect(conditionMatches({ ...all, max_scopes: 1 }, candidate)).toBe(false);
    expect(conditionMatches({ ...all, application_ids: [OTHER] }, candidate)).toBe(false);
    expect(conditionMatches({ ...all, task_id_prefix: "x" }, candidate)).toBe(false);
  });
});
