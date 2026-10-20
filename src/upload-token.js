import { createHmac, timingSafeEqual, randomBytes } from "node:crypto";

export const UPLOAD_TOKEN_TTL_MS = 5 * 60 * 1000;

function sign(payloadB64, secret) {
  return createHmac("sha256", secret).update(payloadB64).digest("base64url");
}

// Signed, single-use, short-lived token for the presigned-upload-URL flow.
// Format: <base64url(JSON payload)>.<base64url(HMAC-SHA256 signature)>
export function mintUploadToken({ sessionId, pagePath, filename, contentType, secret }) {
  const payload = {
    sid: sessionId,
    pagePath,
    filename,
    contentType: contentType || "application/octet-stream",
    exp: Date.now() + UPLOAD_TOKEN_TTL_MS,
    nonce: randomBytes(16).toString("hex"),
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const token = `${payloadB64}.${sign(payloadB64, secret)}`;
  return { token, payload };
}

export function verifyUploadToken(token, secret) {
  const [payloadB64, sig] = String(token || "").split(".");
  if (!payloadB64 || !sig) throw new Error("Malformed upload token");

  const expected = Buffer.from(sign(payloadB64, secret));
  const actual = Buffer.from(sig);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new Error("Invalid upload token signature");
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    throw new Error("Malformed upload token");
  }

  if (!payload.exp || Date.now() > payload.exp) {
    throw new Error("Upload token expired");
  }

  return payload;
}
