import { describe, expect, test } from "bun:test";
import { sanitizeEntry, sanitizeString } from "../src/sanitizer";

describe("SafeHAR 9-Stage Regex Sanitizer Engine", () => {
  // Stage 1: Auth Bearer JWT
  test("Stage 1: masks Bearer JWT token in Authorization header", () => {
    const raw =
      "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature";
    const res = sanitizeString(raw);
    expect(res.text).toBe("Bearer [REDACTED_JWT_TOKEN]");
    expect(res.redactedCount).toBe(1);
    expect(res.hasSensitiveAuth).toBe(true);
  });

  // Stage 2: Auth Basic Credential
  test("Stage 2: masks Basic credentials in Authorization header", () => {
    const raw = "Basic YWRtaW46c2VjcmV0cGFzc3dvcmQ=";
    const res = sanitizeString(raw);
    expect(res.text).toBe("Basic [REDACTED_BASIC_AUTH]");
    expect(res.redactedCount).toBe(1);
    expect(res.hasSensitiveAuth).toBe(true);
  });

  // Stage 3: Web Session Cookies
  test("Stage 3: masks Web Session Cookies (PHPSESSID, JSESSIONID, ASP.NET_SessionId, connect.sid)", () => {
    const raw =
      "PHPSESSID=38974a9f8b0e8d; JSESSIONID=0A1B2C3D4E5F; ASP.NET_SessionId=aspnet12345; connect.sid=s%3Aabcdef.xyz123";
    const res = sanitizeString(raw);
    expect(res.text).toContain("PHPSESSID=[REDACTED_SESSION_ID]");
    expect(res.text).toContain("JSESSIONID=[REDACTED_SESSION_ID]");
    expect(res.text).toContain("ASP.NET_SessionId=[REDACTED_SESSION_ID]");
    expect(res.text).toContain("connect.sid=[REDACTED_SESSION_ID]");
    expect(res.redactedCount).toBe(4);
    expect(res.hasSensitiveAuth).toBe(true);
  });

  // Stage 4: OAuth & Refresh Tokens
  test("Stage 4: masks OAuth tokens in query or postData", () => {
    const raw =
      "https://example.com/callback?access_token=ya29.a0ARrdaM-abcdefgh123456&client_secret=GOCSPX-secret123456789";
    const res = sanitizeString(raw);
    expect(res.text).toBe(
      "https://example.com/callback?access_token=[REDACTED_OAUTH_TOKEN]&client_secret=[REDACTED_OAUTH_TOKEN]",
    );
    expect(res.redactedCount).toBe(2);
    expect(res.hasSensitiveAuth).toBe(true);
  });

  // Stage 5: Stripe Secret / Restricted Keys
  test("Stage 5: masks Stripe sk_live and rk_live keys", () => {
    const fakeSk = ["sk", "live", "51NABC1234567890abcdefghijklmnopqrstuvwxyz"].join("_");
    const fakeRk = ["rk", "live", "51NABC1234567890abcdefghijklm"].join("_");
    const raw = `${fakeSk} and ${fakeRk}`;
    const res = sanitizeString(raw);
    expect(res.text).toBe("[REDACTED_STRIPE_SECRET_KEY] and [REDACTED_STRIPE_SECRET_KEY]");
    expect(res.redactedCount).toBe(2);
    expect(res.hasSensitiveAuth).toBe(true);
  });

  // Stage 6: AWS Access Key ID
  test("Stage 6: masks AWS AKIA and ASIA access keys", () => {
    const raw = "AWS keys: AKIAIOSFODNN7EXAMPLE and temporary ASIAIOSFODNN7EXAMPLE";
    const res = sanitizeString(raw);
    expect(res.text).toBe(
      "AWS keys: [REDACTED_AWS_ACCESS_KEY] and temporary [REDACTED_AWS_ACCESS_KEY]",
    );
    expect(res.redactedCount).toBe(2);
    expect(res.hasSensitiveAuth).toBe(true);
  });

  // Stage 7: GitHub Access Token
  test("Stage 7: masks GitHub personal access tokens (ghp, gho, ghu)", () => {
    const raw = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";
    const res = sanitizeString(raw);
    expect(res.text).toBe("[REDACTED_GITHUB_TOKEN]");
    expect(res.redactedCount).toBe(1);
    expect(res.hasSensitiveAuth).toBe(true);
  });

  // Stage 8: Email Address (PII)
  test("Stage 8: masks email addresses in text body", () => {
    const raw = "User contact: john.doe+billing@company.co.id reached out.";
    const res = sanitizeString(raw);
    expect(res.text).toBe("User contact: [REDACTED_EMAIL_ADDRESS] reached out.");
    expect(res.redactedCount).toBe(1);
  });

  // Stage 9: Payment Card (PAN)
  test("Stage 9: masks Payment Cards (Visa, MasterCard, Amex)", () => {
    const visa = "Visa: 4111111111111111";
    const mc = "MasterCard: 5500000000000004";
    const amex = "Amex: 378282246310005";

    expect(sanitizeString(visa).text).toBe("Visa: [REDACTED_PAYMENT_CARD]");
    expect(sanitizeString(mc).text).toBe("MasterCard: [REDACTED_PAYMENT_CARD]");
    expect(sanitizeString(amex).text).toBe("Amex: [REDACTED_PAYMENT_CARD]");
  });

  // Complete HAR entry sanitization test
  test("Sanitizes full HAR entry structure correctly and produces summary", () => {
    const mockEntry = {
      request: {
        method: "POST",
        url: "https://api.stripe.com/v1/charges?client_secret=secret1234567890abcdef",
        headers: [
          { name: "Authorization", value: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig" },
          { name: "Cookie", value: "connect.sid=session123456; theme=dark" },
        ],
        cookies: [{ name: "connect.sid", value: "session123456" }],
        queryString: [{ name: "client_secret", value: "secret1234567890abcdef" }],
        postData: {
          mimeType: "application/json",
          text: JSON.stringify({
            email: "support@stripe.com",
            card: "4111111111111111",
            api_key: ["sk", "live", "51NABC1234567890abcdefghijk"].join("_"),
          }),
        },
      },
      response: {
        status: 200,
        headers: [{ name: "Set-Cookie", value: "PHPSESSID=phpsess12345; Path=/" }],
        cookies: [{ name: "PHPSESSID", value: "phpsess12345" }],
        content: {
          mimeType: "text/plain",
          text: "Notification sent to user@domain.com from server AKIAIOSFODNN7EXAMPLE",
        },
      },
    };

    const { sanitizedEntry, summary } = sanitizeEntry(mockEntry, 0);

    // Verify request redactions
    expect(sanitizedEntry.request.headers[0].value).toBe("Bearer [REDACTED_JWT_TOKEN]");
    expect(sanitizedEntry.request.cookies[0].value).toBe("[REDACTED_SESSION_ID]");
    expect(sanitizedEntry.request.postData.text).toContain("[REDACTED_EMAIL_ADDRESS]");
    expect(sanitizedEntry.request.postData.text).toContain("[REDACTED_PAYMENT_CARD]");
    expect(sanitizedEntry.request.postData.text).toContain("[REDACTED_STRIPE_SECRET_KEY]");

    // Verify response redactions
    expect(sanitizedEntry.response.cookies[0].value).toBe("[REDACTED_SESSION_ID]");
    expect(sanitizedEntry.response.content.text).toContain("[REDACTED_EMAIL_ADDRESS]");
    expect(sanitizedEntry.response.content.text).toContain("[REDACTED_AWS_ACCESS_KEY]");

    // Verify summary
    expect(summary.method).toBe("POST");
    expect(summary.status).toBe(200);
    expect(summary.hasSensitiveAuth).toBe(true);
    expect(summary.redactedFieldsCount).toBeGreaterThan(5);
  });
});
