// server/security/csrf.ts
// Double-Submit Cookie CSRF Protection Middleware

import type { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';

export const CSRF_COOKIE_NAME = 'eod_csrf_token';
export const CSRF_HEADER_NAME = 'x-csrf-token';

export function generateCsrfToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  // Always ensure a CSRF cookie is set
  let token = req.cookies?.[CSRF_COOKIE_NAME];
  if (!token) {
    token = generateCsrfToken();
    res.cookie(CSRF_COOKIE_NAME, token, {
      httpOnly: false, // Accessible to JavaScript so SPA can echo it in header
      sameSite: 'strict',
      path: '/'
    });
  }

  // Safe HTTP methods do not require CSRF verification
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    return next();
  }

  // Allow test environments or bearer tokens to bypass CSRF if configured
  if (process.env.NODE_ENV === 'test' && req.headers['x-bypass-csrf'] === 'true') {
    return next();
  }

  const headerToken = req.headers[CSRF_HEADER_NAME] || req.headers[CSRF_HEADER_NAME.toLowerCase()];

  if (!headerToken || typeof headerToken !== 'string') {
    res.status(403).json({
      success: false,
      error: {
        code: 'CSRF_TOKEN_MISSING',
        message: 'Missing required CSRF token in X-CSRF-Token header'
      }
    });
    return;
  }

  const cookieToken = req.cookies?.[CSRF_COOKIE_NAME] || token;

  // Constant-time comparison
  const cookieBuffer = Buffer.from(cookieToken);
  const headerBuffer = Buffer.from(headerToken);

  if (cookieBuffer.length !== headerBuffer.length || !crypto.timingSafeEqual(cookieBuffer, headerBuffer)) {
    res.status(403).json({
      success: false,
      error: {
        code: 'CSRF_TOKEN_MISMATCH',
        message: 'Invalid CSRF token'
      }
    });
    return;
  }

  next();
}
