import { getAuthSecret } from '@/lib/auth';

// 给 /api/proxy/m3u8-filter?url=... 这类需要长期可用的 episodes URL 用 HMAC 签名带出，
// 让代理路由可以脱离 cookie 鉴权。
//
// 起因：原生播放器 (ExoPlayer / AVPlayer) 不会共享 React Native fetch 的 cookie jar，
// 走 cookie middleware 的代理路由对 OrionTV 等 TV 客户端总是 401，源全挂。
// 用 ?exp=...&sig=... 自带证明，路由侧自己验签即可豁免 cookie middleware，
// 同时不会沦为开放代理 (没有签名的请求一律 403)。

const TOKEN_VERSION = 'v1';
const DEFAULT_TTL_SECONDS = 24 * 60 * 60;

function base64UrlEncode(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function hmacSign(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return base64UrlEncode(sig);
}

export interface M3u8FilterToken {
  exp: number; // unix seconds
  sig: string; // base64url(HMAC-SHA256(version|url|exp))
}

/**
 * 给指定上游 URL 签发一个短期有效的代理 token。
 * 失败 (密钥缺失) 返回 null —— 此时调用方会生成不带签名的 URL，
 * 路由侧的验证也会拒绝；这种状态只会在 AUTH_SECRET 配置错误时出现。
 */
export async function signM3u8FilterToken(
  url: string,
  ttlSeconds: number = DEFAULT_TTL_SECONDS,
): Promise<M3u8FilterToken | null> {
  const secret = getAuthSecret();
  if (!secret) return null;
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const sig = await hmacSign(secret, `${TOKEN_VERSION}|${url}|${exp}`);
  return { exp, sig };
}

export async function verifyM3u8FilterToken(
  url: string,
  exp: number,
  sig: string,
): Promise<boolean> {
  if (!sig || !Number.isFinite(exp) || exp <= 0) return false;
  if (exp < Math.floor(Date.now() / 1000)) return false;
  const secret = getAuthSecret();
  if (!secret) return false;

  const expected = await hmacSign(secret, `${TOKEN_VERSION}|${url}|${exp}`);

  // 常数时间比较
  if (expected.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  }
  return diff === 0;
}
