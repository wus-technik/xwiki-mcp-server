import { Router } from "express";
import { verifyUploadToken } from "./upload-token.js";
import { sessionCtxFrom } from "./auth-middleware.js";
import { XWikiAuthError } from "./xwiki-client.js";

// Separate, higher cap than the source_url fetch path's MAX_SOURCE_URL_BYTES (50MB, in
// xwiki-client.js). That limit guards against SSRF/abuse via an arbitrary attacker-supplied
// URL; this route instead requires an already-authenticated session plus a short-lived
// signed single-use token, so it carries real local files (e.g. training videos, ~120-150MB).
export const MAX_UPLOAD_ROUTE_BYTES = 500 * 1024 * 1024;

// Reads the raw PUT body straight off the request stream (no body-parser involved —
// express.json()/urlencoded() ignore non-matching Content-Types and leave the stream
// untouched), capped at the same size limit as the source_url fetch path.
function readBodyWithLimit(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    req.on("data", (chunk) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxBytes) {
        // Don't destroy the socket here — it's shared with the response we're about to
        // send. Just stop buffering and let the remaining request bytes drain and be
        // discarded (the `settled` guard above skips further chunks).
        fail(new Error(`Upload exceeds maximum allowed size (${maxBytes} bytes)`));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks));
    });
    req.on("error", fail);
  });
}

// Plain HTTP route for the presigned-upload-URL flow (not behind the OAuth bearer
// middleware — a bare `curl -T` can't send a Bearer token). Auth is the signed,
// single-use token itself plus the session it was minted for.
export function createUploadRouter({ sessionSecret, xwikiClient, store, maxBytes = MAX_UPLOAD_ROUTE_BYTES }) {
  const router = Router();

  router.put("/uploads/:token", async (req, res) => {
    let payload;
    try {
      payload = verifyUploadToken(req.params.token, sessionSecret);
    } catch (e) {
      return res.status(401).type("text/plain").send(e.message);
    }

    // Reserve the nonce first, in ONE mutate (mutate runs sequentially, so check-and-set is
    // atomic: of two parallel PUTs exactly one wins). The nonce stays consumed on any later
    // failure - the URL is one-time. A failed store write means nothing was reserved and
    // nothing is uploaded.
    try {
      const now = Date.now();
      const used = await store.mutate((state) => {
        const exp = state.uploadNonces[payload.nonce];
        if (typeof exp === "number" && exp > now) return true;
        state.uploadNonces[payload.nonce] = payload.exp;
        return false;
      });
      if (used) return res.status(409).type("text/plain").send("Upload token already used");
    } catch {
      return res.status(503).type("text/plain").send("Upload temporarily unavailable");
    }

    const sessionCtx = sessionCtxFrom(store, payload.sid, store.read().sessions[payload.sid]);
    if (!sessionCtx) {
      return res.status(401).type("text/plain").send("Session expired or not found");
    }

    let bytes;
    try {
      bytes = await readBodyWithLimit(req, maxBytes);
    } catch (e) {
      return res.status(413).type("text/plain").send(e.message);
    }

    try {
      const downloadUrl = await xwikiClient.putAttachmentBytes(
        payload.pagePath,
        payload.filename,
        bytes,
        payload.contentType,
        sessionCtx,
      );
      return res.status(201).type("text/plain").send(downloadUrl);
    } catch (e) {
      // The session is deliberately NOT ended here: the /mcp path owns that decision.
      if (e instanceof XWikiAuthError) {
        return res.status(401).type("text/plain").send("XWiki session expired. Please re-authenticate.");
      }
      return res.status(502).type("text/plain").send(e.message);
    }
  });

  return router;
}
