import type { NextRequest } from 'next/server';

import { verifyApiAuth } from './auth';
import { getConfig } from './config';
import { TVBOX_TOKEN_HEADER } from './tvbox-security';

/**
 * Determine whether a TVBox endpoint request is authorized.
 *
 * - When `enableAuth` is disabled, always allow.
 * - When the request carries a valid admin auth cookie we allow it, so the
 *   in-app diagnostic tools keep working without exposing the token in
 *   client-side code.
 * - Otherwise we require the rewritten request to carry the matching token
 *   in the `x-tvbox-token-attempt` header (set by `src/proxy.ts`).
 *
 * NOTE: `verifyApiAuth().isLocalMode` is purely environment-derived
 * (`STORAGE_TYPE=localstorage && no Redis`) — it tells us nothing about
 * whether the current request is from a logged-in admin. Trusting it here
 * would let any anonymous scanner walk past the toggle in localMode
 * deployments, so we deliberately do NOT short-circuit on it.
 */
export async function verifyTvboxAccess(req: NextRequest): Promise<boolean> {
  const cfg = await getConfig();
  const sec = cfg.TVBoxSecurityConfig;
  if (!sec?.enableAuth || !sec?.token) {
    return true;
  }

  const auth = verifyApiAuth(req);
  if (auth.isValid) {
    return true;
  }

  const provided = req.headers.get(TVBOX_TOKEN_HEADER) || '';
  return provided === sec.token;
}
