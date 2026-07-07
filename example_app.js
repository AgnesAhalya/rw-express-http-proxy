'use strict';

/**
 * Secure demonstration app for express-http-proxy.
 *
 * Run:
 *   npm install
 *   PROXY_API_KEY="replace-with-a-long-random-value" node app.js
 *
 * Test:
 *   curl \
 *     -H "x-api-key: replace-with-a-long-random-value" \
 *     "http://127.0.0.1:3000/proxy/json?name=Agnes"
 */

const crypto = require('crypto');
const express = require('express');
const proxy = require('./index');

const HOST = '127.0.0.1';
const PROXY_PORT = readPort(process.env.PORT, 3000);
const UPSTREAM_PORT = readPort(process.env.UPSTREAM_PORT, 4001);
const API_KEY = process.env.PROXY_API_KEY;

const MAX_BODY_BYTES = 64 * 1024;
const MAX_JSON_DEPTH = 20;
const MAX_API_KEY_BYTES = 256;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT = 60;

if (
  typeof API_KEY !== 'string' ||
  API_KEY.length < 24 ||
  Buffer.byteLength(API_KEY, 'utf8') > MAX_API_KEY_BYTES
) {
  console.error(
    'PROXY_API_KEY must contain between 24 and 256 UTF-8 bytes.'
  );
  process.exit(1);
}

function readPort(value, fallback) {
  const port = value === undefined ? fallback : Number(value);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Invalid port value');
  }

  return port;
}

function safeEqual(candidate, expected) {
  const candidateIsValid =
    typeof candidate === 'string' &&
    Buffer.byteLength(candidate, 'utf8') <= MAX_API_KEY_BYTES;

  const expectedIsValid =
    typeof expected === 'string' &&
    expected.length >= 24 &&
    Buffer.byteLength(expected, 'utf8') <= MAX_API_KEY_BYTES;

  const candidateText = candidateIsValid ? candidate : '';
  const expectedText = expectedIsValid ? expected : '';

  const candidateDigest = crypto
    .createHash('sha256')
    .update(candidateText, 'utf8')
    .digest();

  const expectedDigest = crypto
    .createHash('sha256')
    .update(expectedText, 'utf8')
    .digest();

  const hashesMatch = crypto.timingSafeEqual(
    candidateDigest,
    expectedDigest
  );

  return (
    candidateIsValid &&
    expectedIsValid &&
    hashesMatch
  );
}

const FORBIDDEN_JSON_KEYS = new Set([
  '__proto__',
  'prototype',
  'constructor'
]);

function sanitizeJsonValue(
  value,
  errorStatus = 400,
  depth = 0,
  seen = new WeakSet()
) {
  if (depth > MAX_JSON_DEPTH) {
    throw createHttpError(
      errorStatus,
      'JSON payload is too deeply nested'
    );
  }

  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return value;
  }

  if (typeof value !== 'object') {
    throw createHttpError(
      errorStatus,
      'Unsupported JSON value'
    );
  }

  if (seen.has(value)) {
    throw createHttpError(
      errorStatus,
      'Circular JSON values are not allowed'
    );
  }

  seen.add(value);

  if (Array.isArray(value)) {
    const cleanedArray = value.map((item) =>
      sanitizeJsonValue(
        item,
        errorStatus,
        depth + 1,
        seen
      )
    );

    seen.delete(value);
    return cleanedArray;
  }

  const prototype = Object.getPrototypeOf(value);

  if (
    prototype !== Object.prototype &&
    prototype !== null
  ) {
    throw createHttpError(
      errorStatus,
      'Only plain JSON objects are allowed'
    );
  }

  const cleanedObject = Object.create(null);

  for (const [key, childValue] of Object.entries(value)) {
    if (FORBIDDEN_JSON_KEYS.has(key)) {
      throw createHttpError(
        errorStatus,
        'Unsafe JSON property name'
      );
    }

    cleanedObject[key] = sanitizeJsonValue(
      childValue,
      errorStatus,
      depth + 1,
      seen
    );
  }

  seen.delete(value);
  return cleanedObject;
}

function createHttpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function setSecurityHeaders(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; frame-ancestors 'none'"
  );
  res.setHeader('Cache-Control', 'no-store');

  next();
}

function requireApiKey(req, res, next) {
  const suppliedKey = req.get('x-api-key');

  if (!safeEqual(suppliedKey, API_KEY)) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  return next();
}

const rateBuckets = new Map();

const rateBucketCleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [key, bucket] of rateBuckets.entries()) {
    if (now >= bucket.resetAt) {
      rateBuckets.delete(key);
    }
  }
}, RATE_WINDOW_MS);

rateBucketCleanupTimer.unref();

function rateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip;

  let bucket = rateBuckets.get(key);

  if (!bucket || now >= bucket.resetAt) {
    bucket = {
      count: 0,
      resetAt: now + RATE_WINDOW_MS
    };

    rateBuckets.set(key, bucket);
  }

  bucket.count += 1;

  res.setHeader('RateLimit-Limit', String(RATE_LIMIT));
  res.setHeader(
    'RateLimit-Remaining',
    String(Math.max(0, RATE_LIMIT - bucket.count))
  );

  if (bucket.count > RATE_LIMIT) {
    res.setHeader(
      'Retry-After',
      String(
        Math.max(
          1,
          Math.ceil((bucket.resetAt - now) / 1000)
        )
      )
    );

    return res.status(429).json({
      error: 'Too many requests'
    });
  }

  return next();
}

function validateRequest(req, res, next) {
  const allowedMethods = new Set([
    'GET',
    'POST',
    'PUT',
    'PATCH',
    'DELETE'
  ]);

  if (!allowedMethods.has(req.method)) {
    res.setHeader(
      'Allow',
      'GET, POST, PUT, PATCH, DELETE'
    );

    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  if (
    ['POST', 'PUT', 'PATCH'].includes(req.method)
  ) {
    const contentType =
      req.get('content-type') || '';

    const mediaType = contentType
      .split(';', 1)[0]
      .trim()
      .toLowerCase();

    const isJsonContentType =
      mediaType === 'application/json' ||
      mediaType.endsWith('+json');

    if (!isJsonContentType) {
      return res.status(415).json({
        error: 'A JSON content type is required'
      });
    }

    const contentLength = Number(
      req.get('content-length')
    );

    if (
      !Number.isInteger(contentLength) ||
      !Number.isFinite(contentLength) ||
      contentLength < 0
    ) {
      return res.status(411).json({
        error: 'Valid Content-Length required'
      });
    }
    if (
      Number.isFinite(contentLength) &&
      contentLength > MAX_BODY_BYTES
    ) {
      return res.status(413).json({
        error: 'Body too large'
      });
    }
  }

  return next();
}

function cleanForwardedPath(req) {
  const parsed = new URL(
    req.url,
    'http://local.invalid'
  );

  const allowedPaths = new Set([
    '/json',
    '/echo',
    '/missing'
  ]);

  if (!allowedPaths.has(parsed.pathname)) {
    throw createHttpError(
      403,
      'Upstream path is not allowed'
    );
  }

  const output = new URLSearchParams();

  for (const key of ['name', 'page']) {
    const value = parsed.searchParams.get(key);

    if (value !== null) {
      output.set(
        key,
        value.slice(0, 100)
      );
    }
  }

  const query = output.toString();

  return (
    parsed.pathname +
    (query ? `?${query}` : '')
  );
}

function proxyErrorHandler(error, res) {
  const statusCode =
    Number.isInteger(error.statusCode) &&
    error.statusCode >= 400 &&
    error.statusCode <= 599
      ? error.statusCode
      : 502;

  if (res.headersSent) {
    return res.end();
  }

  const safeMessage =
    statusCode === 400 ||
    statusCode === 403 ||
    statusCode === 413
      ? error.message
      : 'Upstream request failed';

  return res.status(statusCode).json({
    error: safeMessage
  });
}

const upstream = express();

upstream.disable('x-powered-by');

upstream.use(
  express.json({
    limit: MAX_BODY_BYTES,
    strict: true
  })
);

upstream.get('/json', (req, res) => {
  res.json({
    source: 'local-upstream',
    name: req.query.name || null
  });
});

upstream.all('/echo', (req, res) => {
  res.json({
    method: req.method,
    body: req.body || null,
    receivedDemoHeader:
      req.get('x-proxy-demo') || null,
    requestId:
      req.get('x-request-id') || null
  });
});

upstream.get('/missing', (req, res) => {
  res.status(404).json({
    error: 'Not found upstream'
  });
});

upstream.use((error, req, res, next) => {
  if (
    error &&
    error.type === 'entity.too.large'
  ) {
    return res.status(413).json({
      error: 'Body too large'
    });
  }

  if (error instanceof SyntaxError) {
    return res.status(400).json({
      error: 'Invalid JSON'
    });
  }

  return next(error);
});

upstream.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    error: 'Internal upstream error'
  });
});

const upstreamServer = upstream.listen(
  UPSTREAM_PORT,
  HOST,
  () => {
    console.log(
      `Local upstream listening on http://${HOST}:${UPSTREAM_PORT}`
    );
  }
);

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', false);

app.use(setSecurityHeaders);

app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();

  res.setHeader(
    'X-Request-Id',
    req.requestId
  );

  return next();
});

app.use(rateLimit);

app.get('/health', (req, res) => {
  res.json({
    status: 'ok'
  });
});

app.use(
  '/proxy',
  requireApiKey,
  validateRequest,
  proxy(
    () =>
      `http://${HOST}:${UPSTREAM_PORT}`,
    {
      limit: MAX_BODY_BYTES,
      timeout: 5000,
      memoizeHost: true,
      parseReqBody: true,
      preserveHostHdr: false,
      reqAsBuffer: true,
      reqBodyEncoding: 'utf-8',

      filter(req) {
        return safeEqual(
          req.get('x-api-key'),
          API_KEY
        );
      },

      proxyReqPathResolver(req) {
        return cleanForwardedPath(req);
      },

      proxyReqOptDecorator(
        proxyReqOpts,
        srcReq
      ) {
        proxyReqOpts.headers =
          proxyReqOpts.headers || {};

        delete proxyReqOpts.headers.authorization;
        delete proxyReqOpts.headers.cookie;
        delete proxyReqOpts.headers['x-api-key'];
        delete proxyReqOpts.headers[
          'proxy-authorization'
        ];
        delete proxyReqOpts.headers[
          'proxy-authenticate'
        ];
        delete proxyReqOpts.headers[
          'transfer-encoding'
        ];
        delete proxyReqOpts.headers.connection;
        delete proxyReqOpts.headers.upgrade;
        delete proxyReqOpts.headers.trailer;
        delete proxyReqOpts.headers.te;

        proxyReqOpts.headers[
          'x-proxy-demo'
        ] = 'secure-example';

        proxyReqOpts.headers[
          'x-request-id'
        ] = srcReq.requestId;

        return proxyReqOpts;
      },

      proxyReqBodyDecorator(
        bodyContent,
        srcReq
      ) {
        if (
          !bodyContent ||
          !['POST', 'PUT', 'PATCH'].includes(
            srcReq.method
          )
        ) {
          return bodyContent;
        }

        let body;

        try {
          if (Buffer.isBuffer(bodyContent)) {
            body = JSON.parse(
              bodyContent.toString('utf8')
            );
          } else if (
            typeof bodyContent === 'string'
          ) {
            body = JSON.parse(bodyContent);
          } else {
            body = bodyContent;
          }
        } catch (error) {
          throw createHttpError(
            400,
            'Invalid JSON body'
          );
        }

        if (
          body === null ||
          Array.isArray(body) ||
          typeof body !== 'object'
        ) {
          throw createHttpError(
            400,
            'JSON body must be an object'
          );
        }

        const cleaned =
          sanitizeJsonValue(body, 400);

        cleaned.proxied = true;

        return JSON.stringify(cleaned);
      },

      userResHeaderDecorator(headers) {
        const safeHeaders = Object.assign(
          Object.create(null),
          headers
        );

        delete safeHeaders['set-cookie'];
        delete safeHeaders.server;
        delete safeHeaders['x-powered-by'];
        delete safeHeaders[
          'proxy-authenticate'
        ];
        delete safeHeaders[
          'transfer-encoding'
        ];
        delete safeHeaders.connection;
        delete safeHeaders.upgrade;
        delete safeHeaders.trailer;

        safeHeaders['cache-control'] =
          'no-store';

        safeHeaders[
          'x-content-type-options'
        ] = 'nosniff';

        return safeHeaders;
      },

      userResDecorator(
        proxyRes,
        proxyResData
      ) {
        const contentType = String(
          proxyRes.headers[
            'content-type'
          ] || ''
        ).toLowerCase();

        const mediaType = contentType
          .split(';', 1)[0]
          .trim();

        const isJsonContentType =
          mediaType === 'application/json' ||
          mediaType.endsWith('+json');

        if (!isJsonContentType) {
          return proxyResData;
        }

        let parsed;

        try {
          parsed = JSON.parse(
            proxyResData.toString('utf8')
          );
        } catch (error) {
          throw createHttpError(
            502,
            'Upstream returned invalid JSON'
          );
        }

        const cleanedResponse =
          sanitizeJsonValue(parsed, 502);

        return JSON.stringify({
          data: cleanedResponse,
          passedThroughProxy: true
        });
      },

      skipToNextHandlerFilter(proxyRes) {
        return proxyRes.statusCode === 404;
      },

      proxyErrorHandler
    }
  )
);

app.use('/proxy', (req, res) => {
  res.status(404).json({
    error: 'Proxy route not found'
  });
});

app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  if (
    error &&
    error.type === 'entity.too.large'
  ) {
    return res.status(413).json({
      error: 'Body too large'
    });
  }

  if (error instanceof SyntaxError) {
    return res.status(400).json({
      error: 'Invalid JSON'
    });
  }

  if (
    Number.isInteger(error.statusCode) &&
    error.statusCode >= 400 &&
    error.statusCode <= 499
  ) {
    return res
      .status(error.statusCode)
      .json({
        error: error.message
      });
  }

  return res.status(500).json({
    error: 'Internal server error'
  });
});

const proxyServer = app.listen(
  PROXY_PORT,
  HOST,
  () => {
    console.log(
      `Secure proxy listening on http://${HOST}:${PROXY_PORT}`
    );
  }
);

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }

    server.close(() => resolve());
  });
}

async function shutdown(signal) {
  console.log(
    `${signal} received; shutting down.`
  );

  clearInterval(rateBucketCleanupTimer);
  rateBuckets.clear();

  const forceExitTimer = setTimeout(() => {
    process.exit(1);
  }, 5000);

  forceExitTimer.unref();

  await Promise.all([
    closeServer(proxyServer),
    closeServer(upstreamServer)
  ]);

  clearTimeout(forceExitTimer);
  process.exit(0);
}

process.once('SIGINT', () => {
  void shutdown('SIGINT');
});

process.once('SIGTERM', () => {
  void shutdown('SIGTERM');
});