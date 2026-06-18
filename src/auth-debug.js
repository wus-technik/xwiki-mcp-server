function requestMeta(req = {}) {
  return {
    method: req.method,
    path: req.originalUrl || req.url,
    userAgent: req.headers?.["user-agent"] || "",
  };
}

export function createAuthDebugLogger(enabled = false) {
  function log(level, event, req, extra = {}) {
    if (!enabled) return;
    const payload = {
      event,
      ...requestMeta(req),
      ...extra,
    };
    console[level](`[auth] ${JSON.stringify(payload)}`);
  }

  return {
    info(event, req, extra) {
      log("info", event, req, extra);
    },
    warn(event, req, extra) {
      log("warn", event, req, extra);
    },
  };
}
