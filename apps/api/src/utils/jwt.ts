import {
  createLocalJWKSet,
  decodeProtectedHeader,
  importPKCS8,
  type JSONWebKeySet,
  type JWTPayload,
  jwtVerify,
  SignJWT,
} from "jose";

// Bounded cache for jose-parsed private keys: signing is the hottest path and
// re-parsing the PEM on every request churns short-lived CryptoKey allocations.
// Sized for a handful of tenants' active keys; FIFO eviction on overflow.
const MAX_KEY_CACHE_SIZE = 64;
type ImportedPrivateKey = Awaited<ReturnType<typeof importPKCS8>>;
const privateKeyCache = new Map<string, ImportedPrivateKey>();

async function getImportedPrivateKey(pem: string): Promise<ImportedPrivateKey> {
  const cached = privateKeyCache.get(pem);
  if (cached) return cached;
  const key = await importPKCS8(pem, "ES256");
  if (privateKeyCache.size >= MAX_KEY_CACHE_SIZE) {
    const oldest = privateKeyCache.keys().next().value;
    if (oldest !== undefined) privateKeyCache.delete(oldest);
  }
  privateKeyCache.set(pem, key);
  return key;
}

/** Sign `claims` as-is (caller sets iss/sub/aud/exp/iat/jti); header `ES256`, `kid`, `at+jwt`. */
export async function signAccessToken(
  privateKeyPem: string,
  kid: string,
  claims: JWTPayload,
): Promise<string> {
  const key = await getImportedPrivateKey(privateKeyPem);
  return new SignJWT(claims).setProtectedHeader({ alg: "ES256", kid, typ: "at+jwt" }).sign(key);
}

export interface VerifyAccessTokenOptions {
  issuer: string;
  audience?: string;
}

/** Verify signature (ES256 only, key picked by `kid` from `jwks`), `typ`, `iss`, `exp`, optional `aud`. */
export async function verifyAccessToken(
  token: string,
  jwks: JSONWebKeySet,
  options: VerifyAccessTokenOptions,
): Promise<JWTPayload> {
  const { payload } = await jwtVerify(token, createLocalJWKSet(jwks), {
    algorithms: ["ES256"],
    typ: "at+jwt",
    issuer: options.issuer,
    audience: options.audience,
  });
  return payload;
}

/** Read the unverified protected header; `{}` for anything that is not a JWS. */
export function decodeHeader(token: string): { kid?: string; alg?: string } {
  try {
    const { kid, alg } = decodeProtectedHeader(token);
    return { kid, alg };
  } catch {
    return {};
  }
}
