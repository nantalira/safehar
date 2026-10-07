/**
 * SAFEHAR DATA CONTRACTS
 * Single source of truth untuk kontrak data, tipe event,
 * dan antarmuka SafeHAR (Web App, Extension, Core Worker).
 */

export type HarWorkerMessageType = "PROGRESS" | "COMPLETE" | "ERROR";

export interface HarWorkerMessage {
  type: HarWorkerMessageType;
  count?: number;
  total?: number;
  message?: string;
}

export interface HarEntrySummary {
  id: string;
  method: string;
  url: string;
  status: number;
  redactedFieldsCount: number;
  hasSensitiveAuth: boolean;
}

/**
 * Konfigurasi opsi redaksi lokal di sisi klien.
 */
export interface RedactionOptions {
  maskAuthHeaders: boolean; // Authorization Bearer & Basic
  maskCookies: boolean; // Cookie & Set-Cookie
  maskStripeKeys: boolean; // sk_live_, rk_live_
  maskAwsKeys: boolean; // AKIA...
  maskEmails: boolean; // Alamat email
  maskCreditCards: boolean; // Format PAN 13-16 digit
}

export * from "./seo";
