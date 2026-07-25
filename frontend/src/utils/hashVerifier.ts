/**
 * Hash Verifier — Client-side immutable log signature verification.
 */

export async function computeSHA256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function verifyLogChain(
  entries: Array<{ content: any; previous_hash: string | null; log_hash: string; created_at: string }>
): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const prevHash = i > 0 ? entries[i - 1].log_hash : "GENESIS";
    const payload = JSON.stringify(entry.content, Object.keys(entry.content).sort()) + prevHash + entry.created_at;
    const expectedHash = await computeSHA256(payload);
    if (expectedHash !== entry.log_hash) {
      errors.push(`Chain broken at index ${i}: hash mismatch`);
    }
  }
  return { valid: errors.length === 0, errors };
}
