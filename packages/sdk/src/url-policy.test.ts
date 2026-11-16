import { describe, expect, it } from "vitest";
import { checkUrl, isLoopback } from "./url-policy.js";

const host = (url: string) => new URL(url).hostname;

describe("isLoopback", () => {
  it("accepts localhost, *.localhost, 127.0.0.0/8 and ::1 only", () => {
    for (const url of [
      "http://localhost/",
      "http://LOCALHOST./",
      "http://api.localhost:3000/",
      "http://127.0.0.1/",
      "http://127.255.255.254/",
      "http://127.1/",
      "http://0x7f.0.0.1/",
      "http://2130706433/",
      "http://[::1]/",
    ]) {
      expect(isLoopback(host(url)), url).toBe(true);
    }
    for (const url of [
      "http://127.evil.com/",
      "http://127.0.0.1.evil.com/",
      "http://localhost.evil.com/",
      "http://evil-localhost/",
      "http://[::ffff:127.0.0.1]/",
      "http://128.0.0.1/",
      "http://10.0.0.1/",
      "http://192.168.1.1/",
      "http://handsal.internal/",
      "http://handsal.local/",
      "http://handsal/",
    ]) {
      expect(isLoopback(host(url)), url).toBe(false);
    }
  });
});

describe("checkUrl", () => {
  const issuer = new URL("https://auth.example.com/t/acme");

  it("compares host and port, with the scheme's default port", () => {
    expect(() => checkUrl("jwksUri", "https://Auth.Example.com.:443/x", {}, issuer)).not.toThrow();
    expect(() => checkUrl("jwksUri", "https://auth.example.com:444/x", {}, issuer)).toThrow(
      /allowCrossOrigin/,
    );
    // http://h is port 80, https://h is port 443: another origin.
    expect(() =>
      checkUrl("jwksUri", "http://auth.example.com/x", { allowInsecureHttp: true }, issuer),
    ).toThrow(/allowCrossOrigin/);
  });

  it("keeps the scheme list and userinfo rule under both options", () => {
    const both = { allowInsecureHttp: true, allowCrossOrigin: true };
    for (const value of ["data:text/plain,x", "ftp://auth.example.com/", "not a url"]) {
      expect(() => checkUrl("tokenUrl", value, both, issuer)).toThrow(
        /^Handsal tokenUrl is invalid$/,
      );
    }
    expect(() => checkUrl("tokenUrl", "https://:secret@auth.example.com/", both, issuer)).toThrow(
      /username or password/,
    );
  });
});
