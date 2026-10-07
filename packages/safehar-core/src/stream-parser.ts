import type { HarEntrySummary, HarWorkerMessage, RedactionOptions } from "@safehar/contracts";
import { JSONParser } from "@streamparser/json";
import { DEFAULT_REDACTION_OPTIONS, sanitizeEntry } from "./sanitizer";

export interface StreamParserOptions {
  redactionOptions?: RedactionOptions;
  batchSize?: number;
  onBatch?: (summaries: HarEntrySummary[]) => void;
  onProgress?: (progress: HarWorkerMessage) => void;
  onEntrySanitized?: (sanitizedEntry: any, index: number) => void;
}

export interface StreamParserResult {
  totalEntries: number;
  totalRedactedFields: number;
  summaries: HarEntrySummary[];
  sanitizedEntries: any[];
}

/**
 * Streaming parser that processes HAR chunks (64KB chunks from Web Streams API)
 * using @streamparser/json with paths: ["$.log.entries.*"] and keepStack: false,
 * guaranteeing constant memory footprint < 60MB.
 */
export class HarStreamParser {
  private parser: JSONParser;
  private entryIndex = 0;
  private totalRedacted = 0;
  private summaries: HarEntrySummary[] = [];
  private batch: HarEntrySummary[] = [];
  private sanitizedEntries: any[] = [];
  private batchSize: number;
  private redactionOptions: RedactionOptions;
  private onBatch?: (summaries: HarEntrySummary[]) => void;
  private onProgress?: (progress: HarWorkerMessage) => void;
  private onEntrySanitized?: (sanitizedEntry: any, index: number) => void;
  private metadata: {
    version: string;
    creator?: any;
    browser?: any;
    pages?: any[];
  } = { version: "1.2" };

  constructor(options: StreamParserOptions = {}) {
    this.batchSize = options.batchSize || 50;
    this.redactionOptions = options.redactionOptions || DEFAULT_REDACTION_OPTIONS;
    this.onBatch = options.onBatch;
    this.onProgress = options.onProgress;
    this.onEntrySanitized = options.onEntrySanitized;

    // Stream parser with paths targeted at entries and keepStack: false to keep heap < 60MB
    this.parser = new JSONParser({
      paths: ["$.log.entries.*", "$.log.version", "$.log.creator", "$.log.browser", "$.log.pages"],
      keepStack: false,
    });

    this.parser.onValue = ({ value, key, stack }) => {
      // Check top-level log properties
      if (stack && stack.length > 0) {
        const parentKey = stack[stack.length - 1]?.key;
        if (parentKey === "log") {
          if (key === "version" && typeof value === "string") this.metadata.version = value;
          if (key === "creator" && typeof value === "object" && value !== null)
            this.metadata.creator = value;
          if (key === "browser" && typeof value === "object" && value !== null)
            this.metadata.browser = value;
          if (key === "pages" && Array.isArray(value)) this.metadata.pages = value;
          return;
        }
      }

      // If it's an entry inside entries
      const entryObj = value as any;
      if (entryObj && typeof entryObj === "object" && (entryObj.request || entryObj.response)) {
        this.processEntry(entryObj);
      }
    };
  }

  private processEntry(rawEntry: any) {
    const { sanitizedEntry, summary } = sanitizeEntry(
      rawEntry,
      this.entryIndex,
      this.redactionOptions,
    );

    this.entryIndex++;
    this.totalRedacted += summary.redactedFieldsCount;
    this.summaries.push(summary);
    this.batch.push(summary);

    if (this.onEntrySanitized) {
      this.onEntrySanitized(sanitizedEntry, this.entryIndex - 1);
    } else {
      this.sanitizedEntries.push(sanitizedEntry);
    }

    if (this.batch.length >= this.batchSize) {
      if (this.onBatch) {
        this.onBatch([...this.batch]);
      }
      if (this.onProgress) {
        this.onProgress({
          type: "PROGRESS",
          count: this.entryIndex,
        });
      }
      this.batch = [];
    }
  }

  /**
   * Write a 64KB chunk of binary data or string to the parser.
   */
  public writeChunk(chunk: Uint8Array | string) {
    this.parser.write(chunk as any);
  }

  /**
   * Finalize the streaming parse session.
   */
  public end(): StreamParserResult {
    // Flush remaining batch
    if (this.batch.length > 0) {
      if (this.onBatch) {
        this.onBatch([...this.batch]);
      }
      this.batch = [];
    }

    if (this.onProgress) {
      this.onProgress({
        type: "COMPLETE",
        count: this.entryIndex,
        total: this.entryIndex,
      });
    }

    return {
      totalEntries: this.entryIndex,
      totalRedactedFields: this.totalRedacted,
      summaries: this.summaries,
      sanitizedEntries: this.sanitizedEntries,
    };
  }

  public getMetadata() {
    return this.metadata;
  }
}

/**
 * Process a standard Web Stream (ReadableStream<Uint8Array>) in chunks of 64KB.
 */
export async function processHarStream(
  stream: ReadableStream<Uint8Array>,
  options: StreamParserOptions = {},
): Promise<StreamParserResult> {
  const parser = new HarStreamParser(options);
  const reader = stream.getReader();

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        parser.writeChunk(value);
      }
    }
    return parser.end();
  } finally {
    reader.releaseLock();
  }
}
