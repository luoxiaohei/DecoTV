import type { AdminConfig } from './admin.types';

export type TVBoxSecurityConfig = NonNullable<
  AdminConfig['TVBoxSecurityConfig']
>;

export const TVBOX_TOKEN_HEADER = 'x-tvbox-token-attempt';

export const TVBOX_TOKEN_MIN_LENGTH = 6;
export const TVBOX_TOKEN_MAX_LENGTH = 64;
const TVBOX_TOKEN_PATTERN = /^[A-Za-z0-9_-]+$/;

const TVBOX_ENDPOINTS = [
  'config',
  'search',
  'diagnose',
  'diagnosis',
  'health',
  'jar-diagnostic',
  'jar-test',
  'spider-status',
] as const;

export type TVBoxEndpoint = (typeof TVBOX_ENDPOINTS)[number];

export const TVBOX_ENDPOINT_SET: ReadonlySet<string> = new Set(TVBOX_ENDPOINTS);

export function getDefaultTVBoxSecurityConfig(): TVBoxSecurityConfig {
  return { enableAuth: false, token: '' };
}

export function isValidTvboxToken(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (
    value.length < TVBOX_TOKEN_MIN_LENGTH ||
    value.length > TVBOX_TOKEN_MAX_LENGTH
  ) {
    return false;
  }
  return TVBOX_TOKEN_PATTERN.test(value);
}

export function generateTvboxToken(length = 24): string {
  const safe = Math.min(
    Math.max(length, TVBOX_TOKEN_MIN_LENGTH),
    TVBOX_TOKEN_MAX_LENGTH,
  );
  const alphabet =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  // Prefer crypto.getRandomValues when available (browser, Node 18+, edge runtime).
  const cryptoObj = (
    globalThis as unknown as {
      crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array };
    }
  ).crypto;
  if (cryptoObj?.getRandomValues) {
    const bytes = new Uint8Array(safe);
    cryptoObj.getRandomValues(bytes);
    let out = '';
    for (let i = 0; i < safe; i += 1) {
      out += alphabet.charAt(bytes[i] % alphabet.length);
    }
    return out;
  }
  let out = '';
  for (let i = 0; i < safe; i += 1) {
    out += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
  }
  return out;
}

export function normalizeTVBoxSecurityConfig(
  raw: AdminConfig['TVBoxSecurityConfig'],
): TVBoxSecurityConfig {
  const defaults = getDefaultTVBoxSecurityConfig();
  if (!raw || typeof raw !== 'object') {
    return defaults;
  }
  const token = isValidTvboxToken(raw.token) ? raw.token : '';
  const enableAuth = Boolean(raw.enableAuth) && token.length > 0;
  return { enableAuth, token };
}

export function buildTvboxBasePath(security?: TVBoxSecurityConfig): string {
  if (security?.enableAuth && security.token) {
    return `/api/tvbox/${security.token}`;
  }
  return '/api/tvbox';
}
