import type { HarEntrySummary, RedactionOptions } from "@safehar/contracts";

export const DEFAULT_REDACTION_OPTIONS: RedactionOptions = {
  maskAuthHeaders: true,
  maskCookies: true,
  maskStripeKeys: true,
  maskAwsKeys: true,
  maskEmails: true,
  maskCreditCards: true,
};

export interface RedactionResult {
  text: string;
  redactedCount: number;
  hasSensitiveAuth: boolean;
}

export interface EntrySanitizationResult {
  sanitizedEntry: any;
  summary: HarEntrySummary;
}

// 9-Stage Regex Redaction Catalog (Sequentially executed as per requirements/SECURITY_AND_REGEX.md)
const REGEX_STAGE_1_JWT = /Bearer\s+ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g;
const REGEX_STAGE_2_BASIC = /Basic\s+[A-Za-z0-9+/=]{10,}/g;
const REGEX_STAGE_3_SESSION_COOKIES =
  /(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid)=[^;]+/gi;
const REGEX_STAGE_4_OAUTH =
  /(access_token|refresh_token|client_secret)=([A-Za-z0-9\-_.~+/%]{16,})/gi;
const REGEX_STAGE_5_STRIPE = /(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}/g;
const REGEX_STAGE_6_AWS = /(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])/g;
const REGEX_STAGE_7_GITHUB = /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}/g;
const REGEX_STAGE_8_EMAIL = /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g;
const REGEX_STAGE_9_CARD = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g;

/**
 * Sanitizes a single string through the 9-stage regex catalog in strict sequential order.
 */
export function sanitizeString(
  input: string,
  options: RedactionOptions = DEFAULT_REDACTION_OPTIONS,
): RedactionResult {
  if (!input || typeof input !== "string") {
    return { text: input, redactedCount: 0, hasSensitiveAuth: false };
  }

  let text = input;
  let count = 0;
  let hasSensitiveAuth = false;

  const countMatches = (regex: RegExp, str: string) => {
    const matches = str.match(regex);
    return matches ? matches.length : 0;
  };

  // Stage 1: Auth Bearer JWT
  if (options.maskAuthHeaders) {
    const matches = countMatches(REGEX_STAGE_1_JWT, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_1_JWT, "Bearer [REDACTED_JWT_TOKEN]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }

  // Stage 2: Auth Basic Credential
  if (options.maskAuthHeaders) {
    const matches = countMatches(REGEX_STAGE_2_BASIC, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_2_BASIC, "Basic [REDACTED_BASIC_AUTH]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }

  // Stage 3: Web Session Cookies
  if (options.maskCookies) {
    const matches = countMatches(REGEX_STAGE_3_SESSION_COOKIES, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_3_SESSION_COOKIES, "$1=[REDACTED_SESSION_ID]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }

  // Stage 4: OAuth & Refresh Tokens
  const oauthMatches = countMatches(REGEX_STAGE_4_OAUTH, text);
  if (oauthMatches > 0) {
    text = text.replace(REGEX_STAGE_4_OAUTH, "$1=[REDACTED_OAUTH_TOKEN]");
    count += oauthMatches;
    hasSensitiveAuth = true;
  }

  // Stage 5: Stripe Secret / Restricted Keys
  if (options.maskStripeKeys) {
    const matches = countMatches(REGEX_STAGE_5_STRIPE, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_5_STRIPE, "[REDACTED_STRIPE_SECRET_KEY]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }

  // Stage 6: AWS Access Key ID
  if (options.maskAwsKeys) {
    const matches = countMatches(REGEX_STAGE_6_AWS, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_6_AWS, "[REDACTED_AWS_ACCESS_KEY]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }

  // Stage 7: GitHub Access Token
  const ghMatches = countMatches(REGEX_STAGE_7_GITHUB, text);
  if (ghMatches > 0) {
    text = text.replace(REGEX_STAGE_7_GITHUB, "[REDACTED_GITHUB_TOKEN]");
    count += ghMatches;
    hasSensitiveAuth = true;
  }

  // Stage 8: Email Address (PII)
  if (options.maskEmails) {
    const matches = countMatches(REGEX_STAGE_8_EMAIL, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_8_EMAIL, "[REDACTED_EMAIL_ADDRESS]");
      count += matches;
    }
  }

  // Stage 9: Payment Card (PAN)
  if (options.maskCreditCards) {
    const matches = countMatches(REGEX_STAGE_9_CARD, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_9_CARD, "[REDACTED_PAYMENT_CARD]");
      count += matches;
    }
  }

  return { text, redactedCount: count, hasSensitiveAuth };
}

/**
 * Sanitizes an individual HAR entry and produces a lightweight HarEntrySummary.
 */
export function sanitizeEntry(
  entry: any,
  index: number,
  options: RedactionOptions = DEFAULT_REDACTION_OPTIONS,
): EntrySanitizationResult {
  const cloned = structuredClone ? structuredClone(entry) : JSON.parse(JSON.stringify(entry));
  let totalRedacted = 0;
  let hasSensitiveAuth = false;

  const sanitizeField = (val: string): string => {
    const res = sanitizeString(val, options);
    totalRedacted += res.redactedCount;
    if (res.hasSensitiveAuth) hasSensitiveAuth = true;
    return res.text;
  };

  // 1. Sanitize Request URL & QueryString
  if (cloned.request) {
    if (cloned.request.url) {
      cloned.request.url = sanitizeField(cloned.request.url);
    }

    if (Array.isArray(cloned.request.queryString)) {
      for (const q of cloned.request.queryString) {
        if (q.value) q.value = sanitizeField(q.value);
      }
    }

    // 2. Sanitize Request Headers
    if (Array.isArray(cloned.request.headers)) {
      for (const h of cloned.request.headers) {
        if (h.value) h.value = sanitizeField(h.value);
      }
    }

    // 3. Sanitize Request Cookies
    if (Array.isArray(cloned.request.cookies)) {
      for (const c of cloned.request.cookies) {
        if (options.maskCookies) {
          const cookieName = c.name?.toLowerCase?.() || "";
          if (
            ["phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid"].includes(cookieName)
          ) {
            c.value = "[REDACTED_SESSION_ID]";
            totalRedacted++;
            hasSensitiveAuth = true;
          } else if (c.value) {
            c.value = sanitizeField(c.value);
          }
        }
      }
    }

    // 4. Sanitize Request PostData
    if (cloned.request.postData?.text) {
      cloned.request.postData.text = sanitizeField(cloned.request.postData.text);
    }
  }

  // 5. Sanitize Response
  if (cloned.response) {
    if (Array.isArray(cloned.response.headers)) {
      for (const h of cloned.response.headers) {
        if (h.value) h.value = sanitizeField(h.value);
      }
    }

    if (Array.isArray(cloned.response.cookies)) {
      for (const c of cloned.response.cookies) {
        if (options.maskCookies) {
          const cookieName = c.name?.toLowerCase?.() || "";
          if (
            ["phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid"].includes(cookieName)
          ) {
            c.value = "[REDACTED_SESSION_ID]";
            totalRedacted++;
            hasSensitiveAuth = true;
          } else if (c.value) {
            c.value = sanitizeField(c.value);
          }
        }
      }
    }

    if (cloned.response.content?.text) {
      cloned.response.content.text = sanitizeField(cloned.response.content.text);
    }
  }

  const method = cloned.request?.method || "GET";
  const url = cloned.request?.url || `unknown-entry-${index}`;
  const status = cloned.response?.status || 0;

  const summary: HarEntrySummary = {
    id: `entry_${index}_${Date.now()}`,
    method,
    url,
    status,
    redactedFieldsCount: totalRedacted,
    hasSensitiveAuth,
  };

  return { sanitizedEntry: cloned, summary };
}
