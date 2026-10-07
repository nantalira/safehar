import { describe, expect, test } from "bun:test";
import {
  type HarEntrySummary,
  type HarWorkerMessage,
  type RedactionOptions,
  SEO_PAGES_DATA,
} from "../src/index";

describe("SafeHAR Contracts Type Verification", () => {
  test("instantiates SafeHAR contracts structure correctly", () => {
    const summary: HarEntrySummary = {
      id: "entry_1",
      method: "POST",
      url: "https://api.stripe.com/v1/charges",
      status: 200,
      redactedFieldsCount: 2,
      hasSensitiveAuth: true,
    };

    const options: RedactionOptions = {
      maskAuthHeaders: true,
      maskCookies: true,
      maskStripeKeys: true,
      maskAwsKeys: true,
      maskEmails: true,
      maskCreditCards: true,
    };

    const workerMsg: HarWorkerMessage = {
      type: "PROGRESS",
      count: 10,
      total: 100,
    };

    expect(summary.id).toBe("entry_1");
    expect(options.maskStripeKeys).toBe(true);
    expect(workerMsg.type).toBe("PROGRESS");
  });

  test("verifies SafeHAR vendor SEO pages catalog", () => {
    expect(SEO_PAGES_DATA.safehar_vendor_keywords.length).toBe(12);
    const zendesk = SEO_PAGES_DATA.safehar_vendor_keywords.find(
      (k) => k.slug === "zendesk-sanitize-har-file",
    );
    expect(zendesk).toBeDefined();
    expect(zendesk?.vendor).toBe("Zendesk");
  });
});
