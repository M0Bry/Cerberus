import { describe, it, expect } from "vitest";
import { encryptField, decryptField } from "./encryption";

describe("AES-GCM field encryption", () => {
  it("round-trips a plaintext", async () => {
    const cipher = await encryptField("hello cerberus", "pass1234");
    expect(cipher).not.toContain("hello cerberus");
    const plain = await decryptField(cipher, "pass1234");
    expect(plain).toBe("hello cerberus");
  });

  it("produces different ciphertexts for the same input (random salt+iv)", async () => {
    const a = await encryptField("same", "pass1234");
    const b = await encryptField("same", "pass1234");
    expect(a).not.toBe(b);
  });

  it("fails to decrypt with the wrong password", async () => {
    const cipher = await encryptField("secret", "pass1234");
    await expect(decryptField(cipher, "wrongpass9")).rejects.toThrow();
  });
});
