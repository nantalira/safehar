import type { RedactionOptions } from "@safehar/contracts";
import { generateSanitizedHarChunks } from "./exporter";
import { HarStreamParser } from "./stream-parser";

export type WorkerInboundMessage =
  | { type: "START"; options?: RedactionOptions; batchSize?: number }
  | { type: "CHUNK"; chunk: Uint8Array | string }
  | { type: "END" };

export type WorkerOutboundMessage =
  | { type: "PROGRESS"; count: number }
  | { type: "BATCH"; summaries: any[] }
  | {
      type: "COMPLETE";
      totalEntries: number;
      totalRedactedFields: number;
      metadata: any;
      sanitizedHarChunks: string[];
    }
  | { type: "ERROR"; error: string };

let currentParser: HarStreamParser | null = null;
let collectedSanitizedEntries: any[] = [];

/**
 * Web Worker event listener for isolated, client-side streaming HAR processing.
 */
if (typeof self !== "undefined" && typeof (self as any).postMessage === "function") {
  self.onmessage = (event: MessageEvent<WorkerInboundMessage>) => {
    const msg = event.data;

    try {
      if (msg.type === "START") {
        collectedSanitizedEntries = [];
        currentParser = new HarStreamParser({
          redactionOptions: msg.options,
          batchSize: msg.batchSize || 50,
          onBatch: (summaries) => {
            self.postMessage({ type: "BATCH", summaries });
          },
          onProgress: (progress) => {
            self.postMessage({ type: "PROGRESS", count: progress.count || 0 });
          },
          onEntrySanitized: (entry) => {
            collectedSanitizedEntries.push(entry);
          },
        });
      } else if (msg.type === "CHUNK") {
        if (!currentParser) {
          throw new Error("Parser not initialized. Send START message first.");
        }
        currentParser.writeChunk(msg.chunk);
      } else if (msg.type === "END") {
        if (!currentParser) {
          throw new Error("Parser not initialized.");
        }
        const result = currentParser.end();
        const metadata = currentParser.getMetadata();

        // Generate sanitized chunks
        const chunks: string[] = [];
        for (const chunk of generateSanitizedHarChunks(metadata, collectedSanitizedEntries)) {
          chunks.push(chunk);
        }

        self.postMessage({
          type: "COMPLETE",
          totalEntries: result.totalEntries,
          totalRedactedFields: result.totalRedactedFields,
          metadata,
          sanitizedHarChunks: chunks,
        });

        // Clear memory
        collectedSanitizedEntries = [];
        currentParser = null;
      }
    } catch (err: any) {
      self.postMessage({
        type: "ERROR",
        error: err?.message || String(err),
      });
    }
  };
}
