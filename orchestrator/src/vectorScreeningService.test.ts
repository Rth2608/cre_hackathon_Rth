import { describe, expect, test } from "bun:test";
import {
  buildCanonicalTextForVector,
  cosineSimilarity,
  decideSimilarityAction,
  pickBestMatch,
  requestIdToPointId
} from "./vectorScreeningService";

describe("vector screening service helpers", () => {
  test("buildCanonicalTextForVector normalizes text and URLs", () => {
    const text = buildCanonicalTextForVector({
      question: "  Will BTC close above 120k? ",
      description: "  Use daily close on major exchange. ",
      resolutionCriteria: "   Coinbase close at UTC 00:00 ",
      sourceUrls: ["https://b.com", " https://a.com "],
      submitterAddress: "0xAbCDEF0000000000000000000000000000000000"
    });
    expect(text).toContain("question=Will BTC close above 120k?");
    expect(text).toContain("sourceUrls=https://a.com|https://b.com");
    expect(text).toContain("submitterAddress=0xabcdef0000000000000000000000000000000000");
  });

  test("cosine similarity behaves as expected", () => {
    expect(cosineSimilarity([1, 0, 0], [1, 0, 0])).toBeCloseTo(1, 6);
    expect(cosineSimilarity([1, 0, 0], [0, 1, 0])).toBeCloseTo(0, 6);
    expect(cosineSimilarity([1, 0], [-1, 0])).toBeCloseTo(-1, 6);
  });

  test("decision thresholds map to duplicate/conflict/allow", () => {
    const duplicate = decideSimilarityAction({
      similarity: 0.991,
      matchedRequestId: "0xdup",
      conflictThreshold: 0.92,
      duplicateThreshold: 0.985
    });
    expect(duplicate.decision).toBe("reject_duplicate");
    expect(duplicate.reason).toContain("vector_duplicate_of_request");

    const conflict = decideSimilarityAction({
      similarity: 0.95,
      matchedRequestId: "0xconflict",
      conflictThreshold: 0.92,
      duplicateThreshold: 0.985
    });
    expect(conflict.decision).toBe("reject_conflict");
    expect(conflict.reason).toContain("vector_conflict_with_request");

    const allow = decideSimilarityAction({
      similarity: 0.5,
      matchedRequestId: "0xok",
      conflictThreshold: 0.92,
      duplicateThreshold: 0.985
    });
    expect(allow.decision).toBe("allow");
  });

  test("pickBestMatch returns null when no comparable vectors", () => {
    expect(pickBestMatch([])).toBeNull();
  });

  test("requestIdToPointId is deterministic UUID-like", () => {
    const idA = requestIdToPointId("0xabc");
    const idB = requestIdToPointId("0xabc");
    const idC = requestIdToPointId("0xdef");
    expect(idA).toBe(idB);
    expect(idA).not.toBe(idC);
    expect(idA).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });
});
