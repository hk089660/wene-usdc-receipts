/**
 * 学校PoC API - Cloudflare Workers (Hono)
 * /v1/school/* と /api/* は Durable Object (SchoolStore) に転送
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { SchoolStore } from './storeDO';
import auditRouter from './audit/router';

type Bindings = {
  CORS_ORIGIN?: string;
  ADMIN_PASSWORD?: string;
  AUDIT_LOG_WRITE_TOKEN?: string;
  SCHOOL_STORE: DurableObjectNamespace;
  AUDIT_LOGS?: R2Bucket;
  AUDIT_INDEX?: KVNamespace;
  AUDIT_IMMUTABLE_MODE?: string;
  AUDIT_IMMUTABLE_INGEST_URL?: string;
  AUDIT_IMMUTABLE_INGEST_TOKEN?: string;
  AUDIT_IMMUTABLE_FETCH_TIMEOUT_MS?: string;
  SECURITY_RATE_LIMIT_ENABLED?: string;
  SECURITY_RATE_LIMIT_READ_PER_MINUTE?: string;
  SECURITY_RATE_LIMIT_MUTATION_PER_MINUTE?: string;
  SECURITY_RATE_LIMIT_AUTH_PER_10_MINUTES?: string;
  SECURITY_RATE_LIMIT_ADMIN_LOGIN_PER_10_MINUTES?: string;
  SECURITY_RATE_LIMIT_VERIFY_PER_MINUTE?: string;
  SECURITY_RATE_LIMIT_GLOBAL_PER_MINUTE?: string;
  SECURITY_RATE_LIMIT_BLOCK_SECONDS?: string;
  SECURITY_MAX_REQUEST_BODY_BYTES?: string;
  SECURITY_ADMIN_EVENT_ISSUE_LIMIT_PER_DAY?: string;
  SECURITY_ADMIN_INVITE_ISSUE_LIMIT_PER_DAY?: string;
  FAIRSCALE_ENABLED?: string;
  FAIRSCALE_FAIL_CLOSED?: string;
  FAIRSCALE_BASE_URL?: string;
  FAIRSCALE_VERIFY_PATH?: string;
  FAIRSCALE_API_KEY?: string;
  FAIRSCALE_TIMEOUT_MS?: string;
  FAIRSCALE_MIN_SCORE?: string;
  FAIRSCALE_ENFORCE_ON_REGISTER?: string;
  FAIRSCALE_ENFORCE_ON_CLAIM?: string;
};

const DEFAULT_CORS = 'https://wene-usdc-receipts.pages.dev';

function addCorsHeaders(response: Response, origin: string): Response {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization, X-Fairscale-Token');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

const app = new Hono<{ Bindings: Bindings }>();

app.use(
  '*',
  cors({
    origin: (origin) => {
      // 開発環境とプレビュー、本番ドメインを許可
      return origin.endsWith('.pages.dev') || origin.includes('localhost') ? origin : (DEFAULT_CORS);
    },
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Accept', 'Authorization', 'X-Fairscale-Token'],
  })
);

async function forwardToDo(c: any): Promise<Response> {
  if (c.req.method === 'OPTIONS') {
    return c.body(null, 204);
  }
  const id = c.env.SCHOOL_STORE.idFromName('default');
  const stub = c.env.SCHOOL_STORE.get(id);
  const res = await stub.fetch(c.req.raw);
  const origin = c.req.header('origin');
  const allowedOrigin = (origin?.endsWith('.pages.dev') || origin?.includes('localhost')) ? origin : (c.env?.CORS_ORIGIN ?? DEFAULT_CORS);
  return addCorsHeaders(res, allowedOrigin);
}

app.all('/v1/school/*', forwardToDo);
app.all('/api/*', forwardToDo);
app.all('/metadata/*', forwardToDo);

// 監査ログは DO 転送の外で処理
app.route('/', auditRouter);

app.get('/', (c) => c.json({ status: 'ok', service: 'wene-usdc-receipts-api' }));
app.get('/health', (c) => c.json({ ok: true }));

export { SchoolStore };

export default {
  fetch(request: Request, env: Bindings, ctx: ExecutionContext) {
    return app.fetch(request, env, ctx);
  },
};
