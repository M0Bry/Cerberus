import { describe, it, expect } from "vitest";
import {
  checkChatMessage,
  checkCompanyName,
  checkContactField,
  checkEmail,
  checkFullName,
  checkOTP,
  checkPassword,
  checkPasswordMatch,
  checkPhone,
  checkSignatureName,
  cleanText,
  validateEmail,
  validatePassword,
  validateDomain,
  validateIP,
  validateOTP,
} from "./validators";

describe("validateEmail", () => {
  it("accepts valid emails", () => {
    expect(validateEmail("user@example.com")).toBe(true);
    expect(validateEmail("a.b+c@sub.domain.co")).toBe(true);
  });
  it("rejects invalid emails", () => {
    expect(validateEmail("nope")).toBe(false);
    expect(validateEmail("a@b")).toBe(false);
    expect(validateEmail("a b@c.com")).toBe(false);
    expect(validateEmail("@x.com")).toBe(false);
  });
});

describe("validatePassword", () => {
  it("accepts a strong password", () => {
    expect(validatePassword("Cerberus123").valid).toBe(true);
  });
  it("collects every unmet rule", () => {
    const r = validatePassword("abc");
    expect(r.valid).toBe(false);
    expect(r.errors).toEqual([
      "At least 8 characters",
      "One uppercase letter",
      "One number",
    ]);
  });
});

describe("validateDomain", () => {
  it("accepts real domains", () => {
    expect(validateDomain("cerberus-ai.com")).toBe(true);
    expect(validateDomain("sub.example.co")).toBe(true);
  });
  it("rejects garbage", () => {
    expect(validateDomain("not a domain")).toBe(false);
    expect(validateDomain("-bad.com")).toBe(false);
    expect(validateDomain("x.c")).toBe(false);
  });
});

describe("validateIP", () => {
  it("accepts valid IPv4", () => {
    expect(validateIP("192.168.0.1")).toBe(true);
    expect(validateIP("0.0.0.0")).toBe(true);
  });
  it("rejects out-of-range octets and shapes", () => {
    expect(validateIP("256.1.1.1")).toBe(false);
    expect(validateIP("1.2.3")).toBe(false);
    expect(validateIP("1.2.3.4.5")).toBe(false);
  });
});

describe("validateOTP", () => {
  it("accepts exactly 6 digits", () => {
    expect(validateOTP("123456")).toBe(true);
  });
  it("rejects wrong length or letters", () => {
    expect(validateOTP("12345")).toBe(false);
    expect(validateOTP("1234567")).toBe(false);
    expect(validateOTP("12a456")).toBe(false);
  });
});

describe("cleanText", () => {
  it("trims and strips control characters but keeps newlines/tabs", () => {
    expect(cleanText("  hi\u0000there\n\tok\u007F  ")).toBe("hi\u0000there\n\tok".replace("\u0000", "") + "");
    expect(cleanText("\u0001abc\u001f")).toBe("abc");
  });
  it("returns stable output for empty strings", () => {
    expect(cleanText("")).toBe("");
  });
});

describe("checkEmail", () => {
  it("passes a normal email", () => {
    expect(checkEmail("user@acme.com")).toBe("");
  });
  it("rejects empty, malformed and overlong values", () => {
    expect(checkEmail("")).toBe("Email is required.");
    expect(checkEmail("nope")).toBeTruthy();
    expect(checkEmail("a@b")).toBeTruthy();
    expect(checkEmail(`a@${"b".repeat(250)}.com`)).toBe("Email is too long.");
  });
});

describe("checkPhone", () => {
  it("allows empty when optional", () => {
    expect(checkPhone("", true)).toBe("");
    expect(checkPhone("", false)).toBe("Phone number is required.");
  });
  it("accepts international formats, rejects garbage", () => {
    expect(checkPhone("+20 100 000 0000")).toBe("");
    expect(checkPhone("0100-000-0000")).toBe("");
    expect(checkPhone("abc")).toBeTruthy();
    expect(checkPhone("1".repeat(21))).toBe("Phone number is too long.");
  });
});

describe("checkPassword", () => {
  it("passes a strong password", () => {
    expect(checkPassword("Cerberus123")).toBe("");
  });
  it("reports short, weak and overlong passwords", () => {
    expect(checkPassword("")).toBe("Password is required.");
    expect(checkPassword("Cerb1")).toContain("at least 8");
    expect(checkPassword("Cerberus")).toContain("One number");
    expect(checkPassword("alllowercase1")).toContain("One uppercase letter");
    expect(checkPassword("A".repeat(129))).toBe("Password is too long.");
  });
});

describe("checkPasswordMatch", () => {
  it("matches identical values", () => {
    expect(checkPasswordMatch("Abc123!x", "Abc123!x")).toBe("");
  });
  it("rejects mismatches", () => {
    expect(checkPasswordMatch("Abc123!x", "Abc123!y")).toBe("Passwords do not match.");
  });
});

describe("checkFullName", () => {
  it("accepts normal names", () => {
    expect(checkFullName("John Doe")).toBe("");
    expect(checkFullName("O'Neil-Smith Jr.")).toBe("");
  });
  it("rejects empty, short, overlong and non-name characters", () => {
    expect(checkFullName("")).toBe("Full name is required.");
    expect(checkFullName("J")).toBe("Full name is too short.");
    expect(checkFullName("A".repeat(101))).toBe("Full name is too long.");
    expect(checkFullName("<script>alert(1)</script>")).toBeTruthy();
    expect(checkFullName("12345")).toBeTruthy();
  });
});

describe("checkCompanyName", () => {
  it("accepts normal company names", () => {
    expect(checkCompanyName("Acme Corp")).toBe("");
    expect(checkCompanyName("ACME & Sons (EG) 2026")).toBe("");
  });
  it("rejects empty/overlong/injection text", () => {
    expect(checkCompanyName("")).toBe("Company name is required.");
    expect(checkCompanyName("A".repeat(101))).toBe("Company name is too long.");
    expect(checkCompanyName("Acme<script>")).toBeTruthy();
  });
});

describe("checkOTP", () => {
  it("passes 6 digits", () => {
    expect(checkOTP("000000")).toBe("");
  });
  it("rejects partial or malformed codes", () => {
    expect(checkOTP("")).toBe("Enter the 6-digit code.");
    expect(checkOTP("12345")).toBeTruthy();
    expect(checkOTP("12a456")).toBeTruthy();
  });
});

describe("checkContactField", () => {
  it("validates name/subject/message rules", () => {
    expect(checkContactField("name", "Jo")).toBe("");
    expect(checkContactField("name", "J")).toBeTruthy();
    expect(checkContactField("subject", "Hello")).toBe("");
    expect(checkContactField("subject", "")).toBe("Subject is required.");
    expect(checkContactField("message", "x".repeat(10))).toBe("");
    expect(checkContactField("message", "short")).toBeTruthy();
    expect(checkContactField("message", "x".repeat(5001))).toContain("too long");
  });
});

describe("checkChatMessage", () => {
  it("passes normal messages", () => {
    expect(checkChatMessage("Start with OSINT")).toBe("");
  });
  it("rejects empty and overlong messages", () => {
    expect(checkChatMessage("   ")).toBe("Type a message first.");
    expect(checkChatMessage("x".repeat(4001))).toContain("too long");
  });
});

describe("checkSignatureName", () => {
  it("accepts a typed legal name", () => {
    expect(checkSignatureName("Jane A. Smith")).toBe("");
  });
  it("rejects short, overlong and non-name input", () => {
    expect(checkSignatureName("")).toBe("Type your full legal name to sign.");
    expect(checkSignatureName("Jo")).toBe("Signature is too short.");
    expect(checkSignatureName("A".repeat(61))).toBe("Signature is too long.");
    expect(checkSignatureName("name<script>")).toBeTruthy();
  });
});
