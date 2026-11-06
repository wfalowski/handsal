import { describe, expect, it } from "vitest";
import { isFormUrlEncoded, parseBasicAuth } from "./helpers.js";

const basic = (raw: string) => `Basic ${Buffer.from(raw, "utf8").toString("base64")}`;

describe("parseBasicAuth", () => {
  it("parses id and secret", () => {
    expect(parseBasicAuth(basic("app_abc:hs_secret"))).toEqual({
      clientId: "app_abc",
      clientSecret: "hs_secret",
    });
  });

  it("percent-decodes both parts and splits on the first colon only", () => {
    expect(parseBasicAuth(basic("my%3Aid:p%40ss:word+x"))).toEqual({
      clientId: "my:id",
      clientSecret: "p@ss:word x",
    });
  });

  it("accepts a case-insensitive scheme", () => {
    expect(parseBasicAuth(basic("a:b").replace("Basic", "basic"))).toEqual({
      clientId: "a",
      clientSecret: "b",
    });
  });

  it.each([
    ["no header", undefined],
    ["empty header", ""],
    ["wrong scheme", `Bearer ${Buffer.from("a:b").toString("base64")}`],
    ["missing colon", basic("no-colon")],
    ["empty client id", basic(":secret")],
    ["empty secret", basic("id:")],
    ["invalid base64", "Basic !!!not-base64"],
    ["malformed percent-encoding", basic("bad%zz:secret")],
    ["scheme without credentials", "Basic "],
  ])("returns null for %s", (_label, header) => {
    expect(parseBasicAuth(header)).toBeNull();
  });
});

describe("isFormUrlEncoded", () => {
  it.each([
    ["application/x-www-form-urlencoded", true],
    ["Application/X-WWW-Form-Urlencoded; charset=UTF-8", true],
    ["application/json", false],
    [undefined, false],
  ])("%s → %s", (contentType, expected) => {
    expect(isFormUrlEncoded(contentType)).toBe(expected);
  });
});
