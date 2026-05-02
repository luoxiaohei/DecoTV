import type { NextRequest } from 'next/server';

import { verifyApiAuth } from './auth';
import { getConfig } from './config';
import { TVBOX_TOKEN_HEADER } from './tvbox-security';

/**
 * Determine whether a TVBox endpoint request is authorized.
 *
 * - When `enableAuth` is disabled, always allow.
 * - When the request is made by an authenticated admin (via cookie) we also
 *   allow it, so the in-app diagnostic tools keep working without ever
 *   exposing the token in client-side code.
 * - Otherwise we require the rewritten request to carry the matching token
 *   in the `x-tvbox-token-attempt` header (set by `src/proxy.ts`).
 */
export async function verifyTvboxAccess(req: NextRequest): Promise<boolean> {
  const cfg = await getConfig();
  const sec = cfg.TVBoxSecurityConfig;
  if (!sec?.enableAuth || !sec?.token) {
    return true;
  }

  const auth = verifyApiAuth(req);
  if (auth.isLocalMode || auth.isValid) {
    return true;
  }

  const provided = req.headers.get(TVBOX_TOKEN_HEADER) || '';
  return provided === sec.token;
}
