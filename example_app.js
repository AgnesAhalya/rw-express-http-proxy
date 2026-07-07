'use strict';

/**
 * Secure demonstration app for this local express-http-proxy source tree.
 *
 * Run:
 *   npm install
 *   PROXY_API_KEY="replace-with-a-long-random-value" node app.js
 *
 * Call:
 *   curl -H "x-api-key: replace-with-a-long-random-value" \
 *     "http://127.0.0.1:3000/proxy/json?name=Agnes"
 *
 * This file starts:
 *   1. A small local upstream API on 127.0.0.1:4001
 *   2. A secured proxy API on 127.0.0.1:3000
 *
 * The upstream is fixed to localhost. Never accept a proxy host from a query
 * parameter, header, or request body because that can create SSRF.
 */

const crypto = require('crypto');
const express = require('express');
const proxy = require('./index');

const PROXY_PORT = readPort(process.env.PORT, 3000);
const UPSTREAM_PORT = readPort(process.env.UPSTREAM_PORT, 4001);
const HOST = '127.0.0.1';
const API_KEY = process.env.PROXY_API_KEY;
const MAX_BODY_BYTES = 64 * 1024;
const RATE_WINDOW_MS = 60 * 1000;
const RATE_LIMIT = 60;

if (!API_KEY || API_KEY.length < 24) {
  console.error('PROXY_API_KEY must contain at least 24 characters.');
  process.exit(1);
}

function readPort(value, fallback) {
  const port = value === undefined ? fallback : Number(value);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Invalid port value');
  }

  return port;
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left || ''), 'utf8');
  const rightBuffer = Buffer.from(String(right || ''), 'utf8');

  return (
    leftBuffer.length === rightBuffer.length &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer)
  );
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
  if (!safeEqual(req.get('x-api-key'), API_KEY)) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  next();
}

const rateBuckets = new Map();

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
      String(Math.ceil((bucket.resetAt - now) / 1000))
    );

    return res.status(429).json({
      error: 'Too many requests'
    });
  }

  next();
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
    return res.status(405).json({
      error: 'Method not allowed'
    });
  }

  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.get('content-type') || '';

    if (!contentType.toLowerCase().startsWith('application/json')) {
      return res.status(415).json({
        error: 'Only application/json is allowed'
      });
    }
  }

  next();
}

function cleanForwardedPath(req) {
  const parsed = new URL(req.url, 'http://local.invalid');

  const allowedPaths = new Set([
    '/json',
    '/echo',
    '/missing'
  ]);

  if (!allowedPaths.has(parsed.pathname)) {
    const error = new Error('Upstream path is not allowed');
    error.statusCode = 403;

    throw error;
  }

  const output = new URLSearchParams();

  for (const key of ['name', 'page']) {
    const value = parsed.searchParams.get(key);

    if (value !== null) {
      output.set(key, value.slice(0, 100));
    }
  }

  const query = output.toString();

  return parsed.pathname + (query ? `?${query}` : '');
}

function proxyErrorHandler(error, res) {
  const status = Number.isInteger(error.statusCode)
    ? error.statusCode
    : 502;

  if (!res.headersSent) {
    return res.status(status).json({
      error:
        status === 403
          ? error.message
          : 'Upstream request failed'
    });
  }

  res.end();
}

/*
 * Local upstream API
 */

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
      req.get('x-proxy-demo') || null
  });
});

upstream.get('/missing', (req, res) => {
  res.status(404).json({
    error: 'Not found upstream'
  });
});

upstream.use((error, req, res, next) => {
  if (error && error.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Body too large'
    });
  }

  if (error instanceof SyntaxError) {
    return res.status(400).json({
      error: 'Invalid JSON'
    });
  }

  next(error);
});

upstream.listen(UPSTREAM_PORT, HOST, () => {
  console.log(
    `Local upstream listening on http://${HOST}:${UPSTREAM_PORT}`
  );
});

/*
 * Secure proxy application
 */

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

  next();
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
    () => `http://${HOST}:${UPSTREAM_PORT}`,
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

      proxyReqOptDecorator(proxyReqOpts, srcReq) {
        proxyReqOpts.headers =
          proxyReqOpts.headers || {};

        delete proxyReqOpts.headers.authorization;
        delete proxyReqOpts.headers.cookie;
        delete proxyReqOpts.headers['x-api-key'];
        delete proxyReqOpts.headers[
          'proxy-authorization'
        ];
        delete proxyReqOpts.headers[
          'transfer-encoding'
        ];
        delete proxyReqOpts.headers.upgrade;

        proxyReqOpts.headers[
          'x-proxy-demo'
        ] = 'secure-example';

        proxyReqOpts.headers[
          'x-request-id'
        ] = srcReq.requestId;

        return proxyReqOpts;
      },

      proxyReqBodyDecorator(bodyContent, srcReq) {
        if (
          !bodyContent ||
          !['POST', 'PUT', 'PATCH'].includes(
            srcReq.method
          )
        ) {
          return bodyContent;
        }

        let body;

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

        if (
          !body ||
          Array.isArray(body) ||
          typeof body !== 'object'
        ) {
          throw new Error(
            'JSON body must be an object'
          );
        }

        const cleaned = Object.create(null);

        for (
          const [key, value] of Object.entries(body)
        ) {
          if (
            ![
              '__proto__',
              'prototype',
              'constructor'
            ].includes(key)
          ) {
            cleaned[key] = value;
          }
        }

        cleaned.proxied = true;

        return JSON.stringify(cleaned);
      },

      userResHeaderDecorator(headers) {
        const safeHeaders = Object.assign(
          {},
          headers
        );

        delete safeHeaders['set-cookie'];
        delete safeHeaders.server;
        delete safeHeaders['x-powered-by'];

        safeHeaders['cache-control'] =
          'no-store';

        safeHeaders['x-content-type-options'] =
          'nosniff';

        return safeHeaders;
      },

      userResDecorator(proxyRes, proxyResData) {
        const contentType = String(
          proxyRes.headers['content-type'] || ''
        );

        if (
          !contentType.includes(
            'application/json'
          )
        ) {
          return proxyResData;
        }

        const parsed = JSON.parse(
          proxyResData.toString('utf8')
        );

        return JSON.stringify({
          data: parsed,
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

  return res.status(500).json({
    error: 'Internal server error'
  });
});

const server = app.listen(
  PROXY_PORT,
  HOST,
  () => {
    console.log(
      `Secure proxy listening on http://${HOST}:${PROXY_PORT}`
    );
  }
);

function shutdown(signal) {
  console.log(
    `${signal} received; shutting down.`
  );

  server.close(() => {
    process.exit(0);
  });

  setTimeout(() => {
    process.exit(1);
  }, 5000).unref();
}

process.on('SIGINT', () => {
  shutdown('SIGINT');
});

process.on('SIGTERM', () => {
  shutdown('SIGTERM');
});