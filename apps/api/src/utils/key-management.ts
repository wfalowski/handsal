import { generateKeyPairSync, randomBytes } from "crypto";

/** Fresh ES256 (P-256) key pair as PEM (`spki` public, `pkcs8` private). */
export function generateEs256KeyPair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

/** Key id `k_YYYY-MM-DD_xxxx` (UTC date + 4 random lowercase hex). */
export function makeKid(date: Date = new Date()): string {
  return `k_${date.toISOString().slice(0, 10)}_${randomBytes(2).toString("hex")}`;
}
