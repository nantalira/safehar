import { describe, expect, test } from "bun:test";
import {
  createSanitizedHarBlob,
  generateSanitizedHarChunks,
  serializeSanitizedHar,
} from "../src/exporter";
import { HarStreamParser, processHarStream } from "../src/stream-parser";

describe("SafeHAR Web Worker Streaming Parser & Exporter (Task 2.1 & 2.3)", () => {
  // Generate sample HAR structure
  const createMockHar = (entryCount: number) => {
    const entries = [];
    for (let i = 0; i < entryCount; i++) {
      entries.push({
        startedDateTime: "2026-10-05T08:00:00.000Z",
        time: 120,
        request: {
          method: i % 2 === 0 ? "POST" : "GET",
          url: `https://api.example.com/v1/resource/${i}?access_token=ya29.a0ARrdaM-1234567890abcdef`,
          headers: [
            { name: "Authorization", value: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig" },
            { name: "Cookie", value: "connect.sid=session_abc123; user_pref=light" },
          ],
          cookies: [{ name: "connect.sid", value: "session_abc123" }],
          postData: {
            mimeType: "application/json",
            text: JSON.stringify({
              userEmail: `test_${i}@customer.com`,
              key: ["sk", "live", "51NABC1234567890abcdefghijk"].join("_"),
            }),
          },
        },
        response: {
          status: 200,
          headers: [{ name: "Content-Type", value: "application/json" }],
          content: {
            mimeType: "application/json",
            text: JSON.stringify({ message: "Success", awsKey: "AKIAIOSFODNN7EXAMPLE" }),
          },
        },
      });
    }

    return {
      log: {
        version: "1.2",
        creator: { name: "Test HAR Agent", version: "1.0" },
        pages: [],
        entries,
      },
    };
  };

  test("Streams 64KB chunks and parses entries incrementally with batching", async () => {
    const mockHar = createMockHar(120);
    const jsonString = JSON.stringify(mockHar);
    const encoder = new TextEncoder();
    const binaryData = encoder.encode(jsonString);

    const batchesReceived: number[] = [];
    const parser = new HarStreamParser({
      batchSize: 50,
      onBatch: (summaries) => {
        batchesReceived.push(summaries.length);
      },
    });

    // Simulate 64KB chunks feeding
    const chunkSize = 64 * 1024;
    for (let offset = 0; offset < binaryData.length; offset += chunkSize) {
      const slice = binaryData.subarray(offset, offset + chunkSize);
      parser.writeChunk(slice);
    }

    const result = parser.end();

    expect(result.totalEntries).toBe(120);
    expect(result.summaries.length).toBe(120);
    // 120 entries with batchSize 50 -> batches: 50, 50, 20
    expect(batchesReceived).toEqual([50, 50, 20]);
    expect(result.totalRedactedFields).toBeGreaterThan(500);

    // Verify metadata was captured
    expect(parser.getMetadata().version).toBe("1.2");
  });

  test("Web Streams API integration via processHarStream", async () => {
    const mockHar = createMockHar(30);
    const jsonString = JSON.stringify(mockHar);
    const encoder = new TextEncoder();
    const binaryData = encoder.encode(jsonString);

    // Create ReadableStream chunked by 16KB
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const chunkSize = 16 * 1024;
        for (let offset = 0; offset < binaryData.length; offset += chunkSize) {
          controller.enqueue(binaryData.subarray(offset, offset + chunkSize));
        }
        controller.close();
      },
    });

    const result = await processHarStream(stream, { batchSize: 10 });
    expect(result.totalEntries).toBe(30);
    expect(result.sanitizedEntries.length).toBe(30);
  });

  test("V8 heap memory constraint verification (< 60MB)", () => {
    // Generate a larger payload (1000 entries)
    const mockHar = createMockHar(1000);
    const jsonString = JSON.stringify(mockHar);
    const binaryData = new TextEncoder().encode(jsonString);

    const initialHeap = process.memoryUsage().heapUsed;

    const parser = new HarStreamParser({ batchSize: 100 });
    const chunkSize = 64 * 1024;
    for (let offset = 0; offset < binaryData.length; offset += chunkSize) {
      parser.writeChunk(binaryData.subarray(offset, offset + chunkSize));
    }
    const result = parser.end();

    const endHeap = process.memoryUsage().heapUsed;
    const heapDiffMb = (endHeap - initialHeap) / (1024 * 1024);

    expect(result.totalEntries).toBe(1000);
    // Heap usage change during parsing should be well under 60MB
    expect(heapDiffMb).toBeLessThan(60);
  });

  test("Reconstructs valid, sanitized .har export file and verifies integrity", () => {
    const mockHar = createMockHar(5);
    const jsonString = JSON.stringify(mockHar);

    const parser = new HarStreamParser();
    parser.writeChunk(new TextEncoder().encode(jsonString));
    const result = parser.end();

    // 1. Serialize using serializeSanitizedHar
    const serializedHar = serializeSanitizedHar(parser.getMetadata(), result.sanitizedEntries);

    // Verify it is a valid parseable JSON HAR file
    const parsedBack = JSON.parse(serializedHar);
    expect(parsedBack.log).toBeDefined();
    expect(parsedBack.log.version).toBe("1.2");
    expect(parsedBack.log.creator.name).toBe("Test HAR Agent");
    expect(parsedBack.log.entries.length).toBe(5);

    // Verify fallback when no creator specified
    const fallbackHar = JSON.parse(serializeSanitizedHar({}, []));
    expect(fallbackHar.log.creator.name).toBe("SafeHAR Sanitizer");

    // Verify all credentials are truly masked in the exported file
    expect(serializedHar).not.toContain("ya29.a0ARrdaM-1234567890abcdef");
    expect(serializedHar).not.toContain(["sk", "live", "51NABC1234567890abcdefghijk"].join("_"));
    expect(serializedHar).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(serializedHar).toContain("[REDACTED_STRIPE_SECRET_KEY]");
    expect(serializedHar).toContain("[REDACTED_AWS_ACCESS_KEY]");
    expect(serializedHar).toContain("[REDACTED_JWT_TOKEN]");

    // 2. Test Blob generation
    const blob = createSanitizedHarBlob(parser.getMetadata(), result.sanitizedEntries);
    expect(blob.type).toContain("application/json");
    expect(blob.size).toBeGreaterThan(0);

    // 3. Test chunk generator
    const chunks = Array.from(
      generateSanitizedHarChunks(parser.getMetadata(), result.sanitizedEntries),
    );
    const joined = chunks.join("");
    const parsedChunks = JSON.parse(joined);
    expect(parsedChunks.log.entries.length).toBe(5);
  });
});
