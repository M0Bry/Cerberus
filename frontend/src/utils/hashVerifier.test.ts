import { describe, it, expect } from "vitest";
import { computeSHA256, verifyLogChain } from "./hashVerifier";

type Entry = { content: any; previous_hash: string | null; log_hash: string; created_at: string };

async function buildChain(lines: string[]): Promise<Entry[]> {
  const entries: Entry[] = [];
  let prev: string | null = null;
  for (const line of lines) {
    const content = { message: line };
    const created_at = new Date().toISOString();
    const payload = JSON.stringify(content, Object.keys(content).sort()) + (prev ?? "GENESIS") + created_at;
    entries.push({ content, previous_hash: prev, log_hash: await computeSHA256(payload), created_at });
    prev = entries[entries.length - 1].log_hash;
  }
  return entries;
}

describe("computeSHA256", () => {
  it("matches the known SHA-256 of 'abc'", async () => {
    expect(await computeSHA256("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });
});

describe("verifyLogChain", () => {
  it("accepts an intact chain", async () => {
    const { valid } = await verifyLogChain(await buildChain(["a", "b", "c"]));
    expect(valid).toBe(true);
  });

  it("detects a tampered entry", async () => {
    const chain = await buildChain(["a", "b", "c"]);
    (chain[1].content as any).message = "TAMPERED";
    const { valid, errors } = await verifyLogChain(chain);
    expect(valid).toBe(false);
    expect(errors.join(" ")).toContain("index 1");
  });
});
