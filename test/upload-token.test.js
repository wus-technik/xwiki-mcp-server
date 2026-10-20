import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mintUploadToken, verifyUploadToken } from "../src/upload-token.js";

const SECRET = "test-secret-32-chars-minimum-pad";

test("mintUploadToken shape: payload carries session/page/filename/contentType/exp/nonce", () => {
  const { token, payload } = mintUploadToken({
    sessionId: "sess-1",
    pagePath: "Main.WebHome",
    filename: "video.mp4",
    contentType: "video/mp4",
    secret: SECRET,
  });
  assert.equal(typeof token, "string");
  assert.ok(token.includes("."));
  assert.equal(payload.sid, "sess-1");
  assert.equal(payload.pagePath, "Main.WebHome");
  assert.equal(payload.filename, "video.mp4");
  assert.equal(payload.contentType, "video/mp4");
  assert.ok(typeof payload.nonce === "string" && payload.nonce.length > 0);
  assert.ok(payload.exp > Date.now());
  assert.ok(payload.exp <= Date.now() + 5 * 60 * 1000);
});

test("mintUploadToken defaults contentType when omitted", () => {
  const { payload } = mintUploadToken({ sessionId: "s", pagePath: "A.B", filename: "f.bin", secret: SECRET });
  assert.equal(payload.contentType, "application/octet-stream");
});

test("verifyUploadToken round-trips a freshly minted token", () => {
  const { token, payload } = mintUploadToken({
    sessionId: "sess-1", pagePath: "Main.WebHome", filename: "f.bin", secret: SECRET,
  });
  const verified = verifyUploadToken(token, SECRET);
  assert.deepEqual(verified, payload);
});

test("verifyUploadToken rejects a tampered/invalid-signature token", () => {
  const { token } = mintUploadToken({ sessionId: "sess-1", pagePath: "A.B", filename: "f.bin", secret: SECRET });
  const [payloadB64] = token.split(".");
  const tampered = `${payloadB64}.deadbeef`;
  assert.throws(() => verifyUploadToken(tampered, SECRET), /Invalid upload token signature/);
});

test("verifyUploadToken rejects a token signed with a different secret", () => {
  const { token } = mintUploadToken({ sessionId: "sess-1", pagePath: "A.B", filename: "f.bin", secret: SECRET });
  assert.throws(() => verifyUploadToken(token, "a-completely-different-secret-32"), /Invalid upload token signature/);
});

test("verifyUploadToken rejects an expired token", () => {
  const payloadB64 = Buffer.from(JSON.stringify({
    sid: "sess-1", pagePath: "A.B", filename: "f.bin", contentType: "application/octet-stream",
    exp: Date.now() - 1000, nonce: "abc",
  })).toString("base64url");
  const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
  assert.throws(() => verifyUploadToken(`${payloadB64}.${sig}`, SECRET), /Upload token expired/);
});

test("verifyUploadToken rejects a malformed token", () => {
  assert.throws(() => verifyUploadToken("not-a-valid-token", SECRET), /Malformed upload token/);
  assert.throws(() => verifyUploadToken("", SECRET), /Malformed upload token/);
});
