/**
 * Exporter utility for reconstructing and downloading validated sanitized .har files.
 */

export interface HarLogMetadata {
  version?: string;
  creator?: {
    name: string;
    version: string;
    comment?: string;
  };
  browser?: {
    name: string;
    version: string;
    comment?: string;
  };
  pages?: any[];
  comment?: string;
}

export const DEFAULT_CREATOR = {
  name: "SafeHAR Sanitizer",
  version: "0.1.0",
  comment: "100% Client-side privacy-first sanitized HAR export",
};

/**
 * Serializes sanitized entries and metadata into a valid HAR JSON string.
 */
export function serializeSanitizedHar(metadata: HarLogMetadata, sanitizedEntries: any[]): string {
  const harObject = {
    log: {
      version: metadata.version || "1.2",
      creator: metadata.creator || DEFAULT_CREATOR,
      browser: metadata.browser,
      pages: metadata.pages || [],
      entries: sanitizedEntries,
      comment: metadata.comment,
    },
  };

  return JSON.stringify(harObject, null, 2);
}

/**
 * Creates an in-browser Blob for instant clean HAR download.
 */
export function createSanitizedHarBlob(metadata: HarLogMetadata, sanitizedEntries: any[]): Blob {
  const jsonString = serializeSanitizedHar(metadata, sanitizedEntries);
  return new Blob([jsonString], { type: "application/json" });
}

/**
 * Generator that streams out serialized HAR JSON chunks to avoid keeping the entire
 * stringified payload in a single contiguous V8 memory buffer.
 */
export function* generateSanitizedHarChunks(
  metadata: HarLogMetadata,
  sanitizedEntries: any[],
): Generator<string> {
  const header = {
    version: metadata.version || "1.2",
    creator: metadata.creator || DEFAULT_CREATOR,
    browser: metadata.browser,
    pages: metadata.pages || [],
  };

  // Yield the opening structure up to "entries": [
  yield `{\n  "log": {\n    "version": ${JSON.stringify(header.version)},\n    "creator": ${JSON.stringify(header.creator)},\n`;
  if (header.browser) {
    yield `    "browser": ${JSON.stringify(header.browser)},\n`;
  }
  if (header.pages && header.pages.length > 0) {
    yield `    "pages": ${JSON.stringify(header.pages)},\n`;
  }
  yield `    "entries": [\n`;

  for (let i = 0; i < sanitizedEntries.length; i++) {
    const entryJson = JSON.stringify(sanitizedEntries[i]);
    const isLast = i === sanitizedEntries.length - 1;
    yield `      ${entryJson}${isLast ? "" : ",\n"}`;
  }

  // Yield closing brackets
  yield `\n    ]\n  }\n}`;
}
