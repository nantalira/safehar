import type { RedactionOptions } from "@safehar/contracts";
import {
  DEFAULT_REDACTION_OPTIONS,
  generateSanitizedHarChunks,
  HarStreamParser,
} from "@safehar/core";

declare const chrome: any;

const STORAGE_KEY = "safehar_user_redaction_options";

// Elements
const fileInput = document.getElementById("file-input") as HTMLInputElement;
const dropZone = document.getElementById("drop-zone") as HTMLDivElement;
const statusEl = document.getElementById("status") as HTMLDivElement;
const statsEl = document.getElementById("stats") as HTMLDivElement;
const entriesCountEl = document.getElementById("entries-count") as HTMLElement;
const redactedCountEl = document.getElementById("redacted-count") as HTMLElement;
const downloadBtn = document.getElementById("download-btn") as HTMLButtonElement;

// Toggles
const toggleAuth = document.getElementById("toggle-auth") as HTMLInputElement;
const toggleCookies = document.getElementById("toggle-cookies") as HTMLInputElement;
const toggleStripe = document.getElementById("toggle-stripe") as HTMLInputElement;
const toggleAws = document.getElementById("toggle-aws") as HTMLInputElement;
const toggleEmails = document.getElementById("toggle-emails") as HTMLInputElement;
const toggleCards = document.getElementById("toggle-cards") as HTMLInputElement;

let collectedSanitizedEntries: any[] = [];
let parsedMetadata: any = {};
let targetFileName = "sanitized-export.har";

/**
 * Load user options from chrome.storage.local (fallback to localStorage if outside extension)
 */
async function loadPreferences(): Promise<RedactionOptions> {
  return new Promise((resolve) => {
    if (globalThis.chrome?.storage?.local) {
      chrome.storage.local.get([STORAGE_KEY], (result: any) => {
        if (result?.[STORAGE_KEY]) {
          resolve(result[STORAGE_KEY]);
        } else {
          resolve(DEFAULT_REDACTION_OPTIONS);
        }
      });
    } else {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        try {
          resolve(JSON.parse(stored));
        } catch {
          resolve(DEFAULT_REDACTION_OPTIONS);
        }
      } else {
        resolve(DEFAULT_REDACTION_OPTIONS);
      }
    }
  });
}

/**
 * Save user options to chrome.storage.local (and fallback to localStorage)
 */
function savePreferences(options: RedactionOptions) {
  if (globalThis.chrome?.storage?.local) {
    chrome.storage.local.set({ [STORAGE_KEY]: options });
  } else {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(options));
  }
}

function getActiveOptions(): RedactionOptions {
  return {
    maskAuthHeaders: toggleAuth ? toggleAuth.checked : true,
    maskCookies: toggleCookies ? toggleCookies.checked : true,
    maskStripeKeys: toggleStripe ? toggleStripe.checked : true,
    maskAwsKeys: toggleAws ? toggleAws.checked : true,
    maskEmails: toggleEmails ? toggleEmails.checked : true,
    maskCreditCards: toggleCards ? toggleCards.checked : true,
  };
}

function syncCheckboxes(options: RedactionOptions) {
  if (toggleAuth) toggleAuth.checked = options.maskAuthHeaders;
  if (toggleCookies) toggleCookies.checked = options.maskCookies;
  if (toggleStripe) toggleStripe.checked = options.maskStripeKeys;
  if (toggleAws) toggleAws.checked = options.maskAwsKeys;
  if (toggleEmails) toggleEmails.checked = options.maskEmails;
  if (toggleCards) toggleCards.checked = options.maskCreditCards;
}

// Attach change listeners to save on change
[toggleAuth, toggleCookies, toggleStripe, toggleAws, toggleEmails, toggleCards].forEach((el) => {
  el?.addEventListener("change", () => {
    savePreferences(getActiveOptions());
  });
});

async function processFile(file: File) {
  targetFileName = `${file.name.replace(/\.har$/i, "")}-sanitized.har`;
  collectedSanitizedEntries = [];
  downloadBtn.classList.add("hidden");
  statsEl.classList.add("hidden");
  statusEl.classList.remove("hidden");
  statusEl.innerText = "Memproses berkas HAR streaming di sisi klien...";

  const parser = new HarStreamParser({
    redactionOptions: getActiveOptions(),
    batchSize: 50,
    onEntrySanitized: (entry) => {
      collectedSanitizedEntries.push(entry);
    },
  });

  const stream = file.stream();
  const reader = stream.getReader();

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        parser.writeChunk(value);
      }
    }

    const res = parser.end();
    parsedMetadata = parser.getMetadata();

    statusEl.classList.add("hidden");
    statsEl.classList.remove("hidden");
    entriesCountEl.innerText = String(res.totalEntries);
    redactedCountEl.innerText = String(res.totalRedactedFields);
    downloadBtn.classList.remove("hidden");
  } catch (err: any) {
    statusEl.innerText = `Galat sanitasi: ${err?.message || err}`;
  } finally {
    reader.releaseLock();
  }
}

// File handlers
fileInput?.addEventListener("change", () => {
  const file = fileInput.files?.[0];
  if (file) processFile(file);
});

dropZone?.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("border-emerald-400");
});

dropZone?.addEventListener("dragleave", () => {
  dropZone.classList.remove("border-emerald-400");
});

dropZone?.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("border-emerald-400");
  const file = e.dataTransfer?.files?.[0];
  if (file) processFile(file);
});

// Download button handler
downloadBtn?.addEventListener("click", () => {
  const chunks: string[] = [];
  for (const chunk of generateSanitizedHarChunks(parsedMetadata, collectedSanitizedEntries)) {
    chunks.push(chunk);
  }
  const blob = new Blob(chunks, { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = targetFileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
});

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", async () => {
  const options = await loadPreferences();
  syncCheckboxes(options);
});
