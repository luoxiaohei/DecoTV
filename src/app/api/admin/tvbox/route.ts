/* eslint-disable no-console */

import { NextRequest, NextResponse } from 'next/server';

import { persistAdminConfigMutation } from '@/lib/admin-config-mutation';
import { verifyApiAuth } from '@/lib/auth';
import { getConfig } from '@/lib/config';
import {
  generateTvboxToken,
  getDefaultTVBoxSecurityConfig,
  isValidTvboxToken,
  TVBOX_TOKEN_MAX_LENGTH,
  TVBOX_TOKEN_MIN_LENGTH,
} from '@/lib/tvbox-security';

export const runtime = 'nodejs';

interface TVBoxSecurityPayload {
  enableAuth?: boolean;
  token?: string;
  generate?: boolean;
}

export async function POST(request: NextRequest) {
  const authResult = verifyApiAuth(request);

  try {
    const body = (await request.json().catch(() => ({}))) as TVBoxSecurityPayload;
    const wantGenerate = body.generate === true;

    let nextToken = '';
    if (wantGenerate) {
      nextToken = generateTvboxToken();
    } else if (typeof body.token === 'string') {
      nextToken = body.token.trim();
    }

    if (nextToken && !isValidTvboxToken(nextToken)) {
      return NextResponse.json(
        {
          error: `路径 token 仅允许字母/数字/下划线/短横线，长度 ${TVBOX_TOKEN_MIN_LENGTH}-${TVBOX_TOKEN_MAX_LENGTH}`,
        },
        { status: 400 },
      );
    }

    const enableAuth = body.enableAuth === true && nextToken.length > 0;

    if (authResult.isLocalMode) {
      // 本地模式下后端无持久化，由前端自行落 localStorage；此处仅校验并回显
      return NextResponse.json({
        ok: true,
        storageMode: 'local',
        TVBoxSecurityConfig: { enableAuth, token: nextToken },
      });
    }

    if (!authResult.isValid) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const username = authResult.username;
    const adminConfig = await getConfig();
    if (username !== process.env.USERNAME) {
      const user = adminConfig.UserConfig.Users.find(
        (item) => item.username === username,
      );
      if (!user || user.role !== 'admin' || user.banned) {
        return NextResponse.json({ error: '权限不足' }, { status: 401 });
      }
    }

    adminConfig.TVBoxSecurityConfig = nextToken
      ? { enableAuth, token: nextToken }
      : getDefaultTVBoxSecurityConfig();

    await persistAdminConfigMutation(adminConfig);

    return NextResponse.json(
      {
        ok: true,
        storageMode: 'cloud',
        TVBoxSecurityConfig: adminConfig.TVBoxSecurityConfig,
      },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } catch (error) {
    console.error('更新 TVBox 安全配置失败:', error);
    return NextResponse.json(
      {
        error: '更新 TVBox 安全配置失败',
        details: (error as Error).message,
      },
      { status: 500 },
    );
  }
}

// 仅生成一个候选 token，给前端"随机生成"按钮使用，不会持久化任何东西
export async function GET(request: NextRequest) {
  const authResult = verifyApiAuth(request);
  if (!authResult.isLocalMode && !authResult.isValid) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  return NextResponse.json(
    { token: generateTvboxToken() },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
