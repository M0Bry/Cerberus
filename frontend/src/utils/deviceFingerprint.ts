/**
 * Device Fingerprint — Browser fingerprint for security logging.
 */

export async function generateFingerprint(): Promise<string> {
  const components: string[] = [];

  components.push(navigator.userAgent);
  components.push(`${screen.width}x${screen.height}x${screen.colorDepth}`);
  components.push(Intl.DateTimeFormat().resolvedOptions().timeZone);
  components.push(navigator.language);
  components.push(navigator.platform);
  components.push(String(navigator.hardwareConcurrency || 0));

  try {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (ctx) {
      ctx.textBaseline = "top";
      ctx.font = "14px Arial";
      ctx.fillText("CerberusAI", 2, 2);
      components.push(canvas.toDataURL().slice(-50));
    }
  } catch {}

  const raw = components.join("|||");
  const encoder = new TextEncoder();
  const data = encoder.encode(raw);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}
