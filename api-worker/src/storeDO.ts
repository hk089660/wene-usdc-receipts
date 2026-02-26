import bs58 from 'bs58';
import nacl from 'tweetnacl';
import type {
  ClaimBody,
  PopProofBody,
  PopProofResponse,
  ParticipationTicketReceipt,
  RegisterBody,
  SchoolClaimResult,
  SchoolClaimResultSuccess,
  UserClaimBody,
  UserClaimResponse,
  UserTicketSyncBody,
  UserTicketSyncItem,
  UserTicketSyncResponse,
} from './types';
import { ClaimStore, normalizeSubject, type IClaimStorage } from './claimLogic';
import type { AuditActor, AuditEvent } from './audit/types';
import { canonicalize, sha256Hex } from './audit/hash';
import { parseAuditImmutableMode, persistImmutableAuditEntry } from './audit/immutable';

const USER_PREFIX = 'user:';
const ADMIN_CODE_PREFIX = 'admin_code:';
const EVENT_OWNER_PREFIX = 'event_owner:';
const TICKET_RECEIPT_CODE_PREFIX = 'ticket_receipt:';
const TICKET_RECEIPT_SUBJECT_PREFIX = 'ticket_receipt_subject:';
const AUDIT_ENTRY_PREFIX = 'audit_entry:';
const CONFIRMATION_CODE_INDEX_PREFIX = 'confirmation_code_index:';
const USER_ID_INDEX_PREFIX = 'user_id_index:';

function userKey(userId: string): string {
  return USER_PREFIX + userId;
}

function adminCodeKey(code: string): string {
  return ADMIN_CODE_PREFIX + code;
}

function eventOwnerKey(eventId: string): string {
  return EVENT_OWNER_PREFIX + eventId;
}

function ticketReceiptByCodeKey(eventId: string, confirmationCode: string): string {
  return `${TICKET_RECEIPT_CODE_PREFIX}${eventId}:${confirmationCode}`;
}

function ticketReceiptBySubjectKey(eventId: string, subject: string): string {
  return `${TICKET_RECEIPT_SUBJECT_PREFIX}${eventId}:${subject}`;
}

function confirmationCodeIndexKey(confirmationCode: string): string {
  return `${CONFIRMATION_CODE_INDEX_PREFIX}${confirmationCode}`;
}

function userIdIndexKey(userIdHash: string): string {
  return `${USER_ID_INDEX_PREFIX}${userIdHash}`;
}

function auditEntryByHashKey(entryHash: string): string {
  return `${AUDIT_ENTRY_PREFIX}${entryHash}`;
}

async function hashString(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hashPin(pin: string): Promise<string> {
  return hashString(pin);
}

function genConfirmationCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => chars[b % chars.length]).join('');
}

export interface Env {
  CORS_ORIGIN?: string;
  ADMIN_PASSWORD?: string;
  ADMIN_DEMO_PASSWORD?: string;
  POP_SIGNER_SECRET_KEY_B64?: string;
  POP_SIGNER_PUBKEY?: string;
  ENFORCE_ONCHAIN_POP?: string;
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
}

const AUDIT_MAX_DEPTH = 4;
const AUDIT_MAX_ARRAY = 20;
const AUDIT_MAX_KEYS = 50;
const AUDIT_MAX_STRING = 160;
const DEFAULT_ADMIN_PASSWORD = 'change-this-in-dashboard';
const AUDIT_LAST_HASH_GLOBAL_KEY = 'audit:lastHash:global';
const MINT_BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const TX_SIGNATURE_BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{64,128}$/;
const POP_CHAIN_GLOBAL_PREFIX = 'pop_chain:lastHash:global:';
const POP_CHAIN_STREAM_PREFIX = 'pop_chain:lastHash:stream:';
const POP_HASH_LEN = 32;
const POP_MESSAGE_VERSION = 2;
const POP_MESSAGE_LEN = 1 + 32 + 32 + 8 + 32 + 32 + 32 + 32 + 8;
const POP_HASH_GENESIS_HEX = '0'.repeat(64);
const USER_ID_CHAIN_LAST_HASH_KEY = 'user_id_chain:last_hash';
const USER_ID_MIN_LENGTH = 3;
const USER_ID_MAX_LENGTH = 32;
const USER_ID_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;
const AUDIT_HISTORY_PREFIX = 'audit_history:';
const AUDIT_INTEGRITY_DEFAULT_LIMIT = 50;
const AUDIT_INTEGRITY_MAX_LIMIT = 200;
const AUDIT_ENTRY_SCAN_LIMIT = 5000;
const IMMUTABLE_AUDIT_SOURCE = 'school-store';
const TOKEN_IMAGE_URL = 'https://wene-usdc-receipts.pages.dev/ticket-token-v2.png';
const MASTER_SEARCH_INDEX_TTL_MS = 30_000;
const MASTER_SEARCH_SQL_KEEP_KEYS = 5;
const MASTER_SEARCH_SQL_TERM_DOC_LIMIT = 4000;
const MASTER_SEARCH_SQL_DOC_CHUNK_SIZE = 250;
const PARTICIPATION_TICKET_RECEIPT_VERSION = 1;
const PARTICIPATION_TICKET_RECEIPT_TYPE = 'participation_audit_receipt';
const PARTICIPATION_TICKET_VERIFY_ENDPOINT = '/api/audit/receipts/verify';
const PARTICIPATION_TICKET_VERIFY_BY_CODE_ENDPOINT = '/api/audit/receipts/verify-code';
const CONFIRMATION_CODE_MAX_ATTEMPTS = 128;
const CONFIRMATION_CODE_LEGACY_SCAN_LIMIT = 20_000;
const SECURITY_RATE_LIMIT_PREFIX = 'security_rate_limit:';
const SECURITY_DEFAULT_BLOCK_SECONDS = 120;
const SECURITY_DEFAULT_READ_PER_MINUTE = 300;
const SECURITY_DEFAULT_MUTATION_PER_MINUTE = 120;
const SECURITY_DEFAULT_AUTH_PER_10_MINUTES = 60;
const SECURITY_DEFAULT_ADMIN_LOGIN_PER_10_MINUTES = 20;
const SECURITY_DEFAULT_VERIFY_PER_MINUTE = 120;
const SECURITY_DEFAULT_GLOBAL_PER_MINUTE = 2000;
const SECURITY_DEFAULT_MAX_REQUEST_BODY_BYTES = 64 * 1024;
const SECURITY_ISSUE_LIMIT_PREFIX = 'security_issue_limit:';
const SECURITY_DEFAULT_ADMIN_EVENT_ISSUE_LIMIT_PER_DAY = 30;
const SECURITY_DEFAULT_ADMIN_INVITE_ISSUE_LIMIT_PER_DAY = 50;
const SECURITY_ISSUE_LIMIT_WINDOW_MS = 24 * 60 * 60 * 1000;
const FAIRSCALE_DEFAULT_TIMEOUT_MS = 2500;
const FAIRSCALE_DEFAULT_MIN_SCORE = 70;
const FAIRSCALE_DEFAULT_VERIFY_PATH = '/v1/risk/score';

type SecurityRatePolicy = {
  key: string;
  windowMs: number;
  maxRequests: number;
  blockMs: number;
};

type SecurityRateState = {
  windowStartMs: number;
  count: number;
  blockedUntilMs: number;
  violations: number;
  lastSeenMs: number;
};

type SecurityIssueLimitPolicy = {
  key: string;
  maxIssues: number;
  windowMs: number;
  code: string;
  message: string;
};

type SecurityIssueLimitState = {
  windowStartMs: number;
  count: number;
  lastIssuedAtMs: number;
};

type FairscaleAction = 'user_register' | 'user_claim' | 'wallet_claim';

type FairscaleDecision = {
  allow: boolean;
  score: number | null;
  reason: string | null;
  decisionId: string | null;
};

type FairscaleEnforcementError = {
  status: number;
  code: 'fairscale_blocked' | 'fairscale_unavailable' | 'fairscale_not_configured';
  action: FairscaleAction;
  message: string;
  score?: number | null;
  minScore?: number;
  reason?: string | null;
  decisionId?: string | null;
  detail?: string;
};

type FairscaleStatus = {
  enabled: boolean;
  failClosed: boolean;
  enforceOnRegister: boolean;
  enforceOnClaim: boolean;
  minScore: number;
  timeoutMs: number;
  endpointConfigured: boolean;
  operationalReady: boolean;
};

type AuditIntegrityIssue = {
  code: string;
  message: string;
  entryHash?: string;
  eventId?: string;
  ref?: string;
};

type AuditIntegrityReport = {
  ok: boolean;
  mode: 'off' | 'best_effort' | 'required';
  checked: number;
  limit: number;
  globalHead: string | null;
  oldestInWindow: string | null;
  verifyImmutable: boolean;
  issues: AuditIntegrityIssue[];
  warnings: string[];
  inspectedAt: string;
};

type RuntimeStatusReport = {
  ready: boolean;
  checkedAt: string;
  checks: {
    adminPasswordConfigured: boolean;
    popEnforced: boolean;
    popSignerConfigured: boolean;
    popSignerPubkey: string | null;
    popSignerError: string | null;
    auditMode: 'off' | 'best_effort' | 'required';
    auditOperationalReady: boolean;
    auditPrimarySinkConfigured: boolean;
    fairscaleEnabled: boolean;
    fairscaleOperationalReady: boolean;
    fairscaleFailClosed: boolean;
    corsOrigin: string | null;
  };
  blockingIssues: string[];
  warnings: string[];
};

type TransferParty = {
  type: string;
  id: string;
};

type TransferAuditPayload = {
  mode: 'onchain' | 'offchain';
  asset: 'ticket_token';
  amount: number | null;
  mint: string | null;
  txSignature: string | null;
  receiptPubkey: string | null;
  sender: TransferParty;
  recipient: TransferParty;
};

type TransferLogView = {
  ts: string;
  event: string;
  eventId: string;
  entryHash: string;
  prevHash: string;
  streamPrevHash: string;
  transfer: TransferAuditPayload;
  pii?: Record<string, string>;
};

type TransferLogRoleView = 'admin' | 'master';

type UserTicketTransferSnapshot = {
  txSignature: string | null;
  receiptPubkey: string | null;
  mint: string | null;
};

type ConfirmationCodeIndexRecord = {
  code: string;
  eventId: string;
  subject: string;
  issuedAt: string;
};

type UserIdIndexRecord = {
  userId: string;
  userIdHash: string;
  chainHash: string;
  prevChainHash: string;
  createdAt: string;
};

type AdminCodeRecord = {
  adminId: string;
  name: string;
  createdAt: string;
  source: 'invite';
  revokedAt: string | null;
  revokedBy: string | null;
};

type OperatorIdentity = {
  role: 'master' | 'admin';
  source: 'master' | 'invite' | 'demo';
  token: string;
  adminId: string;
  name: string;
  actorId: string;
  code?: string;
};

type EventOwnerRecord = {
  adminId: string;
  name: string;
  source: 'master' | 'invite' | 'demo';
  linkedAt: string;
};

type MasterAdminDisclosureEvent = {
  id: string;
  title: string;
  datetime: string;
  host: string;
  state: string;
  claimedCount: number;
  ownerSource: 'master' | 'invite' | 'demo' | 'inferred';
};

type MasterAdminDisclosureUserClaim = {
  ts: string;
  eventId: string;
  eventTitle: string | null;
  transfer: TransferAuditPayload;
  pii?: Record<string, string>;
};

type MasterAdminDisclosureUser = {
  key: string;
  userId: string | null;
  displayName: string | null;
  walletAddress: string | null;
  joinToken: string | null;
  recipientType: string;
  recipientId: string;
  eventIds: string[];
  claims: MasterAdminDisclosureUserClaim[];
};

type MasterAdminDisclosure = {
  adminId: string;
  code: string;
  name: string;
  createdAt: string;
  status: 'active' | 'revoked';
  revokedAt: string | null;
  events: MasterAdminDisclosureEvent[];
  relatedTransferCount: number;
  relatedUsers: MasterAdminDisclosureUser[];
};

type MasterAdminDisclosuresResponse = {
  checkedAt: string;
  strictLevel: 'master_full';
  includeRevoked: boolean;
  transferLimit: number;
  admins: MasterAdminDisclosure[];
};

type MasterSearchKind = 'admin' | 'event' | 'user' | 'claim';

type MasterSearchResultItem = {
  id: string;
  kind: MasterSearchKind;
  title: string;
  subtitle: string;
  detail: string;
};

type MasterSearchIndexDocument = MasterSearchResultItem & {
  searchText: string;
};

type MasterSearchIndexCache = {
  key: string;
  builtAtMs: number;
  builtAt: string;
  docs: MasterSearchIndexDocument[];
  tokenToDocIds: Map<string, number[]>;
};

type MasterSearchSqlIndexMeta = {
  key: string;
  builtAtMs: number;
  builtAt: string;
};

type MasterSearchResponse = {
  checkedAt: string;
  strictLevel: 'master_full';
  query: string;
  includeRevoked: boolean;
  transferLimit: number;
  limit: number;
  total: number;
  indexBuiltAt: string | null;
  items: MasterSearchResultItem[];
};

type ParticipationTicketReceiptValidationIssue = {
  code: string;
  message: string;
  field?: string;
};

type ParticipationTicketReceiptVerification = {
  ok: boolean;
  checkedAt: string;
  receiptId: string;
  eventId: string;
  confirmationCode: string;
  checks: {
    receiptHashValid: boolean;
    entryExists: boolean;
    entryHashValid: boolean;
    confirmationCodeMatches: boolean;
    eventIdMatches: boolean;
    globalChainLinkValid: boolean;
    streamChainLinkValid: boolean;
    immutablePayloadHashMatches: boolean;
    immutableSinksMatch: boolean;
  };
  issues: ParticipationTicketReceiptValidationIssue[];
  proof: {
    entryHash: string;
    prevHash: string;
    streamPrevHash: string;
    immutablePayloadHash: string | null;
    immutableSinks: Array<{
      sink: string;
      ref: string;
      at: string;
    }>;
  };
};

function buildTokenSymbol(title: string): string {
  const cleaned = title.replace(/\s+/g, '').slice(0, 10).toUpperCase();
  return cleaned || 'TICKET';
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function decodeBase64(input: string): Uint8Array {
  const binary = atob(input);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error('invalid hash hex');
  }
  const out = new Uint8Array(POP_HASH_LEN);
  for (let i = 0; i < POP_HASH_LEN; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function readHashHex(raw: string | undefined | null): string {
  if (!raw || raw === 'GENESIS') return POP_HASH_GENESIS_HEX;
  const v = raw.trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(v)) return v;
  throw new Error('invalid hash in storage');
}

function isHashHex(raw: string): boolean {
  return /^[0-9a-f]{64}$/.test(raw.trim().toLowerCase());
}

function parsePeriodIndex(raw: unknown): bigint | null {
  if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0 && Number.isInteger(raw)) {
    return BigInt(raw);
  }
  if (typeof raw === 'string' && /^\d+$/.test(raw.trim())) {
    return BigInt(raw.trim());
  }
  return null;
}

function parseBoundedInt(raw: string | null, fallback: number, min: number, max: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed)) return fallback;
  if (parsed < min) return min;
  if (parsed > max) return max;
  return parsed;
}

function parseOptionalBoundedInt(raw: string | null, fallback: number, max: number): number | null {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed)) return fallback;
  if (parsed <= 0) return null;
  return Math.min(parsed, max);
}

function parseBooleanQuery(raw: string | null, fallback: boolean): boolean {
  if (raw === null) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on') return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') return false;
  return fallback;
}

function parseBooleanEnv(raw: string | undefined, fallback: boolean): boolean {
  if (typeof raw !== 'string') return fallback;
  const normalized = raw.trim().toLowerCase();
  if (!normalized) return fallback;
  if (normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on') return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') return false;
  return fallback;
}

function u64ToLeBytes(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  const dv = new DataView(out.buffer);
  dv.setBigUint64(0, value, true);
  return out;
}

function i64ToLeBytes(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  const dv = new DataView(out.buffer);
  dv.setBigInt64(0, value, true);
  return out;
}

function doStorageAdapter(ctx: DurableObjectState): IClaimStorage {
  return {
    async get(key: string) {
      return ctx.storage.get(key);
    },
    async put(key: string, value: unknown) {
      await ctx.storage.put(key, value);
    },
    async list(prefix: string) {
      return ctx.storage.list({ prefix }) as Promise<Map<string, unknown>>;
    },
  };
}


export class SchoolStore implements DurableObject {
  private store: ClaimStore;

  constructor(private ctx: DurableObjectState, private env: Env) {
    this.store = new ClaimStore(doStorageAdapter(ctx));
  }


  private auditLock: Promise<void> = Promise.resolve();
  private popProofLock: Promise<void> = Promise.resolve();
  private confirmationCodeLock: Promise<void> = Promise.resolve();
  private userIdRegistrationLock: Promise<void> = Promise.resolve();
  private popSignerCache:
    | { secretKey: Uint8Array; signerPubkey: string }
    | null
    | undefined;
  private masterSearchIndexCache: MasterSearchIndexCache | null = null;
  private masterSearchSqlMetaCache: MasterSearchSqlIndexMeta | null = null;
  private masterSearchSqlTablesReady = false;

  private getPopSigner(): { secretKey: Uint8Array; signerPubkey: string } | null {
    if (this.popSignerCache !== undefined) return this.popSignerCache;

    const secretB64 = this.env.POP_SIGNER_SECRET_KEY_B64?.trim() ?? '';
    const signerPubkey = this.env.POP_SIGNER_PUBKEY?.trim() ?? '';
    if (!secretB64 || !signerPubkey) {
      this.popSignerCache = null;
      return null;
    }

    if (!MINT_BASE58_RE.test(signerPubkey)) {
      throw new Error('POP_SIGNER_PUBKEY is invalid');
    }

    let decoded: Uint8Array;
    try {
      decoded = decodeBase64(secretB64);
    } catch {
      throw new Error('POP_SIGNER_SECRET_KEY_B64 is not base64');
    }

    let secretKey: Uint8Array;
    if (decoded.length === 64) {
      secretKey = decoded;
    } else if (decoded.length === 32) {
      secretKey = nacl.sign.keyPair.fromSeed(decoded).secretKey;
    } else {
      throw new Error('POP_SIGNER_SECRET_KEY_B64 must decode to 32-byte seed or 64-byte secret key');
    }

    let configuredPubkey: Uint8Array;
    try {
      configuredPubkey = bs58.decode(signerPubkey);
    } catch {
      throw new Error('POP_SIGNER_PUBKEY is invalid');
    }
    if (configuredPubkey.length !== 32) {
      throw new Error('POP_SIGNER_PUBKEY must decode to 32 bytes');
    }
    const actualPubkey = nacl.sign.keyPair.fromSecretKey(secretKey).publicKey;
    if (!bytesEqual(actualPubkey, configuredPubkey)) {
      throw new Error('POP signer keypair mismatch (POP_SIGNER_SECRET_KEY_B64 / POP_SIGNER_PUBKEY)');
    }

    this.popSignerCache = { secretKey, signerPubkey };
    return this.popSignerCache;
  }

  private isOnchainPopEnforced(): boolean {
    const raw = (this.env.ENFORCE_ONCHAIN_POP ?? '').trim().toLowerCase();
    if (!raw) return true;
    return !(raw === '0' || raw === 'false' || raw === 'off' || raw === 'no');
  }

  private getAuditImmutableMode() {
    return parseAuditImmutableMode(this.env.AUDIT_IMMUTABLE_MODE);
  }

  private getSecurityBodySizeLimitBytes(): number {
    return parseBoundedInt(
      this.env.SECURITY_MAX_REQUEST_BODY_BYTES ?? null,
      SECURITY_DEFAULT_MAX_REQUEST_BODY_BYTES,
      4 * 1024,
      1024 * 1024
    );
  }

  private isSecurityRateLimitEnabled(): boolean {
    return parseBooleanEnv(this.env.SECURITY_RATE_LIMIT_ENABLED, true);
  }

  private getSecurityRateBlockMs(): number {
    const blockSeconds = parseBoundedInt(
      this.env.SECURITY_RATE_LIMIT_BLOCK_SECONDS ?? null,
      SECURITY_DEFAULT_BLOCK_SECONDS,
      10,
      3600
    );
    return blockSeconds * 1000;
  }

  private getSecurityRatePolicy(path: string, method: string): SecurityRatePolicy | null {
    const m = method.toUpperCase();
    if (m === 'OPTIONS') return null;
    if (!this.isApiPath(path)) return null;
    if (path.startsWith('/metadata/')) return null;

    const blockMs = this.getSecurityRateBlockMs();
    const readPerMinute = parseBoundedInt(
      this.env.SECURITY_RATE_LIMIT_READ_PER_MINUTE ?? null,
      SECURITY_DEFAULT_READ_PER_MINUTE,
      30,
      5000
    );
    const mutationPerMinute = parseBoundedInt(
      this.env.SECURITY_RATE_LIMIT_MUTATION_PER_MINUTE ?? null,
      SECURITY_DEFAULT_MUTATION_PER_MINUTE,
      10,
      3000
    );
    const authPer10Minutes = parseBoundedInt(
      this.env.SECURITY_RATE_LIMIT_AUTH_PER_10_MINUTES ?? null,
      SECURITY_DEFAULT_AUTH_PER_10_MINUTES,
      5,
      3000
    );
    const adminLoginPer10Minutes = parseBoundedInt(
      this.env.SECURITY_RATE_LIMIT_ADMIN_LOGIN_PER_10_MINUTES ?? null,
      SECURITY_DEFAULT_ADMIN_LOGIN_PER_10_MINUTES,
      3,
      500
    );
    const verifyPerMinute = parseBoundedInt(
      this.env.SECURITY_RATE_LIMIT_VERIFY_PER_MINUTE ?? null,
      SECURITY_DEFAULT_VERIFY_PER_MINUTE,
      10,
      5000
    );

    if (path === '/api/admin/login') {
      return {
        key: 'admin_login',
        windowMs: 10 * 60 * 1000,
        maxRequests: adminLoginPer10Minutes,
        blockMs: Math.max(blockMs, 5 * 60 * 1000),
      };
    }

    if (
      path === '/api/auth/verify' ||
      path === '/api/users/tickets/sync' ||
      path === '/api/users/register' ||
      /^\/api\/events\/[^/]+\/claim$/.test(path)
    ) {
      return {
        key: 'user_auth',
        windowMs: 10 * 60 * 1000,
        maxRequests: authPer10Minutes,
        blockMs: Math.max(blockMs, 5 * 60 * 1000),
      };
    }

    if (path === '/api/audit/receipts/verify' || path === '/api/audit/receipts/verify-code') {
      return {
        key: 'receipt_verify',
        windowMs: 60 * 1000,
        maxRequests: verifyPerMinute,
        blockMs,
      };
    }

    if (m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE') {
      return {
        key: 'mutating',
        windowMs: 60 * 1000,
        maxRequests: mutationPerMinute,
        blockMs,
      };
    }

    return {
      key: 'read',
      windowMs: 60 * 1000,
      maxRequests: readPerMinute,
      blockMs,
    };
  }

  private parseSecurityRateState(raw: unknown): SecurityRateState | null {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const windowStartMs = Number(obj.windowStartMs);
    const count = Number(obj.count);
    const blockedUntilMs = Number(obj.blockedUntilMs);
    const violations = Number(obj.violations);
    const lastSeenMs = Number(obj.lastSeenMs);
    if (
      !Number.isFinite(windowStartMs) ||
      !Number.isFinite(count) ||
      !Number.isFinite(blockedUntilMs) ||
      !Number.isFinite(violations) ||
      !Number.isFinite(lastSeenMs)
    ) {
      return null;
    }
    return {
      windowStartMs,
      count,
      blockedUntilMs,
      violations,
      lastSeenMs,
    };
  }

  private getClientIpAddress(request: Request): string {
    const cfIp = request.headers.get('CF-Connecting-IP')?.trim();
    if (cfIp) return cfIp;
    const xff = request.headers.get('X-Forwarded-For')?.trim();
    if (xff) {
      const first = xff.split(',')[0]?.trim();
      if (first) return first;
    }
    return 'unknown';
  }

  private rateLimitExceededResponse(policy: SecurityRatePolicy, retryAfterSec: number): Response {
    return Response.json(
      {
        error: 'too many requests',
        code: 'rate_limited',
        bucket: policy.key,
        retryAfterSec,
      },
      {
        status: 429,
        headers: {
          'Retry-After': String(retryAfterSec),
        },
      }
    );
  }

  private async consumeSecurityRateState(
    stateKey: string,
    now: number,
    policy: SecurityRatePolicy
  ): Promise<{ limited: boolean; retryAfterSec: number }> {
    const parsed = this.parseSecurityRateState(await this.ctx.storage.get(stateKey));
    const state: SecurityRateState = parsed ?? {
      windowStartMs: now,
      count: 0,
      blockedUntilMs: 0,
      violations: 0,
      lastSeenMs: now,
    };

    if (state.blockedUntilMs > now) {
      return {
        limited: true,
        retryAfterSec: Math.max(1, Math.ceil((state.blockedUntilMs - now) / 1000)),
      };
    }

    if (now < state.windowStartMs || now - state.windowStartMs >= policy.windowMs) {
      state.windowStartMs = now;
      state.count = 0;
    }

    state.count += 1;
    state.lastSeenMs = now;

    if (state.count > policy.maxRequests) {
      state.violations = Math.min(state.violations + 1, 12);
      const scale = Math.min(2 ** (state.violations - 1), 16);
      const blockMs = policy.blockMs * scale;
      state.blockedUntilMs = now + blockMs;
      await this.ctx.storage.put(stateKey, state);
      return {
        limited: true,
        retryAfterSec: Math.max(1, Math.ceil(blockMs / 1000)),
      };
    }

    await this.ctx.storage.put(stateKey, state);
    return { limited: false, retryAfterSec: 0 };
  }

  private async enforceSecurityBodySizeLimit(request: Request, path: string): Promise<Response | null> {
    const m = request.method.toUpperCase();
    if (!this.isApiPath(path)) return null;
    if (!(m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE')) return null;
    const maxBytes = this.getSecurityBodySizeLimitBytes();

    const contentLengthHeader = request.headers.get('Content-Length');
    if (contentLengthHeader) {
      const contentLength = Number.parseInt(contentLengthHeader, 10);
      if (Number.isFinite(contentLength) && contentLength > maxBytes) {
        return Response.json(
          {
            error: 'payload too large',
            code: 'payload_too_large',
            maxBytes,
          },
          { status: 413 }
        );
      }
      if (Number.isFinite(contentLength) && contentLength >= 0) {
        return null;
      }
    }

    const bodyStream = request.clone().body;
    if (!bodyStream) return null;
    const reader = bodyStream.getReader();
    let totalBytes = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value?.byteLength ?? 0;
      if (totalBytes > maxBytes) {
        return Response.json(
          {
            error: 'payload too large',
            code: 'payload_too_large',
            maxBytes,
          },
          { status: 413 }
        );
      }
    }
    return null;
  }

  private async enforceSecurityRateLimit(request: Request, path: string): Promise<Response | null> {
    if (!this.isSecurityRateLimitEnabled()) return null;
    const policy = this.getSecurityRatePolicy(path, request.method);
    if (!policy) return null;

    const now = Date.now();
    const clientIp = this.getClientIpAddress(request);
    const clientHash = await hashString(`client:${clientIp}`);
    const clientKey = `${SECURITY_RATE_LIMIT_PREFIX}${policy.key}:client:${clientHash}`;
    const clientResult = await this.consumeSecurityRateState(clientKey, now, policy);
    if (clientResult.limited) {
      return this.rateLimitExceededResponse(policy, clientResult.retryAfterSec);
    }

    const globalPerMinute = parseBoundedInt(
      this.env.SECURITY_RATE_LIMIT_GLOBAL_PER_MINUTE ?? null,
      SECURITY_DEFAULT_GLOBAL_PER_MINUTE,
      100,
      50_000
    );
    const globalPolicy: SecurityRatePolicy = {
      key: `${policy.key}_global`,
      windowMs: 60 * 1000,
      maxRequests: globalPerMinute,
      blockMs: policy.blockMs,
    };
    const globalKey = `${SECURITY_RATE_LIMIT_PREFIX}${globalPolicy.key}`;
    const globalResult = await this.consumeSecurityRateState(globalKey, now, globalPolicy);
    if (globalResult.limited) {
      return this.rateLimitExceededResponse(globalPolicy, globalResult.retryAfterSec);
    }

    return null;
  }

  private async enforceSecurityPreflight(request: Request, path: string): Promise<Response | null> {
    const bodySizeError = await this.enforceSecurityBodySizeLimit(request, path);
    if (bodySizeError) return bodySizeError;
    return this.enforceSecurityRateLimit(request, path);
  }

  private parseSecurityIssueLimitState(raw: unknown): SecurityIssueLimitState | null {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const windowStartMs = Number(obj.windowStartMs);
    const count = Number(obj.count);
    const lastIssuedAtMs = Number(obj.lastIssuedAtMs);
    if (!Number.isFinite(windowStartMs) || !Number.isFinite(count) || !Number.isFinite(lastIssuedAtMs)) {
      return null;
    }
    return { windowStartMs, count, lastIssuedAtMs };
  }

  private issueLimitExceededResponse(
    policy: SecurityIssueLimitPolicy,
    retryAfterSec: number,
    limitPerWindow: number
  ): Response {
    return Response.json(
      {
        error: policy.message,
        code: policy.code,
        limitPerWindow,
        retryAfterSec,
      },
      {
        status: 429,
        headers: {
          'Retry-After': String(retryAfterSec),
        },
      }
    );
  }

  private async consumeSecurityIssueLimit(
    policy: SecurityIssueLimitPolicy,
    actorKey: string
  ): Promise<{ limited: boolean; retryAfterSec: number }> {
    const now = Date.now();
    const actorHash = await hashString(`issuer:${policy.key}:${actorKey}`);
    const storageKey = `${SECURITY_ISSUE_LIMIT_PREFIX}${policy.key}:${actorHash}`;
    const parsed = this.parseSecurityIssueLimitState(await this.ctx.storage.get(storageKey));
    const state: SecurityIssueLimitState = parsed ?? {
      windowStartMs: now,
      count: 0,
      lastIssuedAtMs: now,
    };

    if (now < state.windowStartMs || now - state.windowStartMs >= policy.windowMs) {
      state.windowStartMs = now;
      state.count = 0;
    }

    if (state.count >= policy.maxIssues) {
      const retryAfterMs = Math.max(1000, policy.windowMs - (now - state.windowStartMs));
      return {
        limited: true,
        retryAfterSec: Math.max(1, Math.ceil(retryAfterMs / 1000)),
      };
    }

    state.count += 1;
    state.lastIssuedAtMs = now;
    await this.ctx.storage.put(storageKey, state);
    return { limited: false, retryAfterSec: 0 };
  }

  private async enforceAdminEventIssueLimit(operator: OperatorIdentity): Promise<Response | null> {
    const perDay = parseOptionalBoundedInt(
      this.env.SECURITY_ADMIN_EVENT_ISSUE_LIMIT_PER_DAY ?? null,
      SECURITY_DEFAULT_ADMIN_EVENT_ISSUE_LIMIT_PER_DAY,
      5000
    );
    if (perDay === null) return null;
    const policy: SecurityIssueLimitPolicy = {
      key: 'event_issue',
      maxIssues: perDay,
      windowMs: SECURITY_ISSUE_LIMIT_WINDOW_MS,
      code: 'event_issue_limit_exceeded',
      message: 'event issuance limit exceeded',
    };
    const result = await this.consumeSecurityIssueLimit(policy, operator.adminId);
    if (!result.limited) return null;
    return this.issueLimitExceededResponse(policy, result.retryAfterSec, perDay);
  }

  private async enforceAdminInviteIssueLimit(): Promise<Response | null> {
    const perDay = parseOptionalBoundedInt(
      this.env.SECURITY_ADMIN_INVITE_ISSUE_LIMIT_PER_DAY ?? null,
      SECURITY_DEFAULT_ADMIN_INVITE_ISSUE_LIMIT_PER_DAY,
      5000
    );
    if (perDay === null) return null;
    const policy: SecurityIssueLimitPolicy = {
      key: 'admin_invite_issue',
      maxIssues: perDay,
      windowMs: SECURITY_ISSUE_LIMIT_WINDOW_MS,
      code: 'admin_invite_issue_limit_exceeded',
      message: 'admin invite issuance limit exceeded',
    };
    const result = await this.consumeSecurityIssueLimit(policy, 'master');
    if (!result.limited) return null;
    return this.issueLimitExceededResponse(policy, result.retryAfterSec, perDay);
  }

  private getFairscaleStatus(): FairscaleStatus {
    const baseUrl = (this.env.FAIRSCALE_BASE_URL ?? '').trim().replace(/\/+$/, '');
    const enabled = parseBooleanEnv(this.env.FAIRSCALE_ENABLED, Boolean(baseUrl));
    const failClosed = parseBooleanEnv(this.env.FAIRSCALE_FAIL_CLOSED, true);
    const enforceOnRegister = parseBooleanEnv(this.env.FAIRSCALE_ENFORCE_ON_REGISTER, true);
    const enforceOnClaim = parseBooleanEnv(this.env.FAIRSCALE_ENFORCE_ON_CLAIM, true);
    const minScore = parseBoundedInt(
      this.env.FAIRSCALE_MIN_SCORE ?? null,
      FAIRSCALE_DEFAULT_MIN_SCORE,
      0,
      100
    );
    const timeoutMs = parseBoundedInt(
      this.env.FAIRSCALE_TIMEOUT_MS ?? null,
      FAIRSCALE_DEFAULT_TIMEOUT_MS,
      200,
      10000
    );
    const endpointConfigured = Boolean(baseUrl);
    return {
      enabled,
      failClosed,
      enforceOnRegister,
      enforceOnClaim,
      minScore,
      timeoutMs,
      endpointConfigured,
      operationalReady: !enabled || endpointConfigured,
    };
  }

  private getFairscaleVerifyUrl(): string | null {
    const baseUrl = (this.env.FAIRSCALE_BASE_URL ?? '').trim().replace(/\/+$/, '');
    if (!baseUrl) return null;
    const rawPath = (this.env.FAIRSCALE_VERIFY_PATH ?? '').trim();
    if (rawPath && /^https?:\/\//i.test(rawPath)) {
      return rawPath;
    }
    const path = rawPath || FAIRSCALE_DEFAULT_VERIFY_PATH;
    return `${baseUrl}${path.startsWith('/') ? '' : '/'}${path}`;
  }

  private shouldEnforceFairscaleAction(action: FairscaleAction): boolean {
    const status = this.getFairscaleStatus();
    if (!status.enabled) return false;
    if (action === 'user_register') return status.enforceOnRegister;
    return status.enforceOnClaim;
  }

  private extractFairscaleToken(request: Request, body: unknown): string {
    const headerToken = request.headers.get('X-Fairscale-Token')?.trim();
    if (headerToken) return headerToken.slice(0, 2048);
    if (body && typeof body === 'object' && 'fairscaleToken' in body) {
      const raw = (body as { fairscaleToken?: unknown }).fairscaleToken;
      if (typeof raw === 'string' && raw.trim()) {
        return raw.trim().slice(0, 2048);
      }
    }
    return '';
  }

  private parseFairscaleDecision(raw: unknown, minScore: number): FairscaleDecision {
    const obj = raw && typeof raw === 'object' ? raw as Record<string, unknown> : {};
    const riskRaw = obj.risk;
    const risk = riskRaw && typeof riskRaw === 'object' ? riskRaw as Record<string, unknown> : null;
    const scoreRaw =
      this.normalizeNumberField(obj.score) ??
      this.normalizeNumberField(obj.riskScore) ??
      (risk ? this.normalizeNumberField(risk.score) : null);
    const score = scoreRaw === null ? null : Math.max(0, Math.min(100, scoreRaw));

    const decisionTextRaw =
      typeof obj.decision === 'string'
        ? obj.decision
        : risk && typeof risk.decision === 'string'
          ? risk.decision
          : '';
    const decisionText = decisionTextRaw.trim().toLowerCase();

    let allow: boolean | null = null;
    if (typeof obj.allow === 'boolean') {
      allow = obj.allow;
    } else if (risk && typeof risk.allow === 'boolean') {
      allow = risk.allow;
    } else if (decisionText) {
      if (decisionText === 'allow' || decisionText === 'pass' || decisionText === 'approved' || decisionText === 'ok') {
        allow = true;
      } else if (
        decisionText === 'deny' ||
        decisionText === 'block' ||
        decisionText === 'reject' ||
        decisionText === 'challenge' ||
        decisionText === 'review'
      ) {
        allow = false;
      }
    }

    const challengeRequired =
      obj.challengeRequired === true ||
      (risk && risk.challengeRequired === true);
    if (challengeRequired) {
      allow = false;
    }
    if (score !== null && score < minScore) {
      allow = false;
    }
    if (allow === null) {
      allow = score === null ? true : score >= minScore;
    }

    const reason =
      typeof obj.reason === 'string'
        ? obj.reason.trim()
        : typeof obj.message === 'string'
          ? obj.message.trim()
          : risk && typeof risk.reason === 'string'
            ? risk.reason.trim()
            : '';
    const decisionIdRaw =
      typeof obj.decisionId === 'string'
        ? obj.decisionId
        : typeof obj.id === 'string'
          ? obj.id
          : risk && typeof risk.decisionId === 'string'
            ? risk.decisionId
            : '';

    return {
      allow,
      score,
      reason: reason || null,
      decisionId: decisionIdRaw.trim() || null,
    };
  }

  private async evaluateFairscaleDecision(params: {
    request: Request;
    action: FairscaleAction;
    eventId?: string;
    userId?: string;
    subject?: string;
    fairscaleToken?: string;
  }): Promise<FairscaleDecision> {
    const status = this.getFairscaleStatus();
    const verifyUrl = this.getFairscaleVerifyUrl();
    if (!verifyUrl) {
      throw new Error('fairscale_not_configured');
    }

    const apiKey = (this.env.FAIRSCALE_API_KEY ?? '').trim();
    const ipAddress = this.getClientIpAddress(params.request);
    const ipHash = await hashString(`ip:${ipAddress}`);
    const subjectHash = params.subject ? await hashString(`subject:${params.subject}`) : null;
    const userIdHash = params.userId ? await hashString(`user:${params.userId}`) : null;
    const eventIdHash = params.eventId ? await hashString(`event:${params.eventId}`) : null;
    const userAgentRaw = params.request.headers.get('User-Agent') ?? '';
    const userAgent = userAgentRaw.trim().slice(0, 512);
    const nowIso = new Date().toISOString();

    const payload = {
      version: 1,
      source: 'instant-grant-core',
      action: params.action,
      checkedAt: nowIso,
      subjectHash,
      userIdHash,
      eventIdHash,
      ipAddress: ipAddress === 'unknown' ? null : ipAddress,
      ipHash,
      userAgent: userAgent || null,
      attestationToken: params.fairscaleToken?.trim() || null,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort('fairscale-timeout'), status.timeoutMs);
    try {
      const res = await fetch(verifyUrl, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'content-type': 'application/json',
          ...(apiKey ? { authorization: `Bearer ${apiKey}`, 'x-api-key': apiKey } : {}),
        },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        throw new Error(`fairscale_http_${res.status}`);
      }
      const json = await res.json().catch(() => ({}));
      return this.parseFairscaleDecision(json, status.minScore);
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error('fairscale_timeout');
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private fairscaleErrorResponse(error: FairscaleEnforcementError): Response {
    return Response.json(
      {
        error: error.message,
        code: error.code,
        action: error.action,
        ...(typeof error.minScore === 'number' ? { minScore: error.minScore } : {}),
        ...(typeof error.score === 'number' ? { score: error.score } : {}),
        ...(error.reason ? { reason: error.reason } : {}),
        ...(error.decisionId ? { decisionId: error.decisionId } : {}),
        ...(error.detail ? { detail: error.detail } : {}),
      },
      { status: error.status }
    );
  }

  private mapFairscaleErrorToSchoolClaimResult(error: FairscaleEnforcementError): SchoolClaimResult {
    if (error.code === 'fairscale_blocked') {
      const detail = error.reason ? ` (${error.reason})` : '';
      return {
        success: false,
        error: {
          code: 'eligibility',
          message: `FairScale判定により参加条件を満たしていないため受け付けできません${detail}`,
        },
      };
    }
    return {
      success: false,
      error: {
        code: 'retryable',
        message: 'FairScale判定サービスが一時的に利用できないため、時間を置いて再試行してください。',
      },
    };
  }

  private async enforceFairscaleRisk(params: {
    request: Request;
    action: FairscaleAction;
    eventId?: string;
    userId?: string;
    subject?: string;
    fairscaleToken?: string;
  }): Promise<FairscaleEnforcementError | null> {
    const status = this.getFairscaleStatus();
    if (!this.shouldEnforceFairscaleAction(params.action)) {
      return null;
    }
    if (!status.operationalReady) {
      if (!status.failClosed) {
        return null;
      }
      return {
        status: 503,
        code: 'fairscale_not_configured',
        action: params.action,
        message: 'fairscale verification endpoint is not configured',
      };
    }

    try {
      const decision = await this.evaluateFairscaleDecision(params);
      if (decision.allow) {
        return null;
      }
      return {
        status: 403,
        code: 'fairscale_blocked',
        action: params.action,
        message: 'fairscale sybil check blocked this request',
        minScore: status.minScore,
        score: decision.score,
        reason: decision.reason,
        decisionId: decision.decisionId,
      };
    } catch (err) {
      if (!status.failClosed) {
        console.error('[fairscale] verification failed but allowed (fail-open mode)', err);
        return null;
      }
      const detail = err instanceof Error ? err.message : String(err);
      return {
        status: 503,
        code: 'fairscale_unavailable',
        action: params.action,
        message: 'fairscale verification is temporarily unavailable',
        detail,
      };
    }
  }

  private isMutatingMethod(method: string): boolean {
    const m = method.toUpperCase();
    return m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE';
  }

  private isAuditFailCloseExemptRoute(path: string, method: string): boolean {
    const m = method.toUpperCase();
    if (m !== 'POST') return false;
    return path === '/api/admin/login' || path === '/api/admin/invite' || path === '/api/admin/rename' || path === '/api/admin/revoke';
  }

  private isAuditFailClosed(path: string, method: string): boolean {
    if (this.getAuditImmutableMode() !== 'required') return false;
    if (!this.isMutatingMethod(method)) return false;
    if (this.isAuditFailCloseExemptRoute(path, method)) return false;
    return true;
  }

  private isEventOnchainConfigured(event: { solanaMint?: string; solanaAuthority?: string; solanaGrantId?: string } | null | undefined): boolean {
    if (!event) return false;
    return Boolean(
      typeof event.solanaMint === 'string' && event.solanaMint.trim() &&
      typeof event.solanaAuthority === 'string' && event.solanaAuthority.trim() &&
      typeof event.solanaGrantId === 'string' && event.solanaGrantId.trim()
    );
  }

  private getOnchainProofFields(body: {
    walletAddress?: unknown;
    txSignature?: unknown;
    receiptPubkey?: unknown;
  }): { walletAddress: string; txSignature: string; receiptPubkey: string } {
    const walletAddress = typeof body.walletAddress === 'string' ? body.walletAddress.trim() : '';
    const txSignature = typeof body.txSignature === 'string' ? body.txSignature.trim() : '';
    const receiptPubkey = typeof body.receiptPubkey === 'string' ? body.receiptPubkey.trim() : '';
    return { walletAddress, txSignature, receiptPubkey };
  }

  private validateOnchainProofFields(fields: {
    walletAddress: string;
    txSignature: string;
    receiptPubkey: string;
  }): string | null {
    if (!fields.walletAddress || !MINT_BASE58_RE.test(fields.walletAddress)) {
      return 'walletAddress is required for on-chain claim';
    }
    if (!fields.txSignature || !TX_SIGNATURE_BASE58_RE.test(fields.txSignature)) {
      return 'txSignature is required for on-chain claim';
    }
    if (!fields.receiptPubkey || !MINT_BASE58_RE.test(fields.receiptPubkey)) {
      return 'receiptPubkey is required for on-chain claim';
    }
    return null;
  }

  private hasAnyOnchainProofField(fields: {
    walletAddress: string;
    txSignature: string;
    receiptPubkey: string;
  }): boolean {
    return Boolean(fields.txSignature || fields.receiptPubkey);
  }

  private async buildPopEntryHash(params: {
    prevHash: Uint8Array;
    streamPrevHash: Uint8Array;
    auditHash: Uint8Array;
    grant: Uint8Array;
    claimer: Uint8Array;
    periodIndex: bigint;
    issuedAt: bigint;
  }): Promise<Uint8Array> {
    const encoder = new TextEncoder();
    const periodBytes = u64ToLeBytes(params.periodIndex);
    const issuedAtBytes = i64ToLeBytes(params.issuedAt);
    const domain = encoder.encode('we-ne:pop:v2');
    const input = new Uint8Array(
      domain.length +
      params.prevHash.length +
      params.streamPrevHash.length +
      params.auditHash.length +
      params.grant.length +
      params.claimer.length +
      periodBytes.length +
      issuedAtBytes.length
    );

    let offset = 0;
    input.set(domain, offset); offset += domain.length;
    input.set(params.prevHash, offset); offset += params.prevHash.length;
    input.set(params.streamPrevHash, offset); offset += params.streamPrevHash.length;
    input.set(params.auditHash, offset); offset += params.auditHash.length;
    input.set(params.grant, offset); offset += params.grant.length;
    input.set(params.claimer, offset); offset += params.claimer.length;
    input.set(periodBytes, offset); offset += periodBytes.length;
    input.set(issuedAtBytes, offset);

    const digest = await crypto.subtle.digest('SHA-256', input);
    return new Uint8Array(digest);
  }

  private buildPopProofMessage(params: {
    grant: Uint8Array;
    claimer: Uint8Array;
    periodIndex: bigint;
    prevHash: Uint8Array;
    streamPrevHash: Uint8Array;
    auditHash: Uint8Array;
    entryHash: Uint8Array;
    issuedAt: bigint;
  }): Uint8Array {
    const out = new Uint8Array(POP_MESSAGE_LEN);
    let offset = 0;
    out[offset] = POP_MESSAGE_VERSION;
    offset += 1;
    out.set(params.grant, offset); offset += 32;
    out.set(params.claimer, offset); offset += 32;
    out.set(u64ToLeBytes(params.periodIndex), offset); offset += 8;
    out.set(params.prevHash, offset); offset += 32;
    out.set(params.streamPrevHash, offset); offset += 32;
    out.set(params.auditHash, offset); offset += 32;
    out.set(params.entryHash, offset); offset += 32;
    out.set(i64ToLeBytes(params.issuedAt), offset);
    return out;
  }

  private async issuePopClaimProof(body: PopProofBody): Promise<PopProofResponse> {
    const task = this.popProofLock.then(async () => {
      const signer = this.getPopSigner();
      if (!signer) {
        throw new Error('PoP signer is not configured');
      }

      const eventId = typeof body?.eventId === 'string' ? body.eventId.trim() : '';
      const confirmationCode = typeof body?.confirmationCode === 'string' ? body.confirmationCode.trim() : '';
      const grantRaw = typeof body?.grant === 'string' ? body.grant.trim() : '';
      const claimerRaw = typeof body?.claimer === 'string' ? body.claimer.trim() : '';
      const periodIndex = parsePeriodIndex(body?.periodIndex);

      if (!eventId || !confirmationCode || !grantRaw || !claimerRaw || periodIndex === null || periodIndex < BigInt(0)) {
        throw new Error('invalid PoP proof request');
      }
      if (!MINT_BASE58_RE.test(grantRaw) || !MINT_BASE58_RE.test(claimerRaw)) {
        throw new Error('invalid grant/claimer format');
      }
      const maxU64 = (BigInt(1) << BigInt(64)) - BigInt(1);
      if (periodIndex > maxU64) {
        throw new Error('periodIndex out of range');
      }

      const event = await this.store.getEvent(eventId);
      if (!event) {
        throw new Error('event not found');
      }
      if (event.state && event.state !== 'published') {
        throw new Error('event not available');
      }

      const ticketReceipt = await this.getParticipationTicketReceipt(eventId, '', confirmationCode);
      if (!ticketReceipt) {
        throw new Error('off-chain ticket receipt not found');
      }
      const receiptVerification = await this.verifyParticipationTicketReceipt(ticketReceipt);
      if (!receiptVerification.ok) {
        throw new Error('off-chain ticket receipt verification failed');
      }

      const grant = bs58.decode(grantRaw);
      const claimer = bs58.decode(claimerRaw);
      if (grant.length !== 32 || claimer.length !== 32) {
        throw new Error('invalid grant/claimer bytes');
      }

      const globalKey = `${POP_CHAIN_GLOBAL_PREFIX}${grantRaw}`;
      const streamKey = `${POP_CHAIN_STREAM_PREFIX}${grantRaw}`;
      const prevHashHex = readHashHex(await this.ctx.storage.get<string>(globalKey));
      const streamPrevHashHex = readHashHex(await this.ctx.storage.get<string>(streamKey));
      const prevHash = hexToBytes(prevHashHex);
      const streamPrevHash = hexToBytes(streamPrevHashHex);
      const issuedAt = BigInt(Math.floor(Date.now() / 1000));
      const auditHashHex = readHashHex(ticketReceipt.receiptHash);
      const auditHash = hexToBytes(auditHashHex);

      // Bind PoP proof issuance to a verified off-chain participation receipt.
      const auditAnchor = await this.appendAuditLog(
        'POP_CLAIM_PROOF_ANCHOR',
        { type: 'wallet', id: this.maskActorId(claimerRaw) },
        {
          eventId,
          confirmationCode,
          receiptId: ticketReceipt.receiptId,
          receiptHash: ticketReceipt.receiptHash,
          receiptVerifiedAt: receiptVerification.checkedAt,
          grant: grantRaw,
          claimer: claimerRaw,
          periodIndex: periodIndex.toString(),
          prevHash: prevHashHex,
          streamPrevHash: streamPrevHashHex,
        },
        `pop:${eventId}`
      );

      const entryHash = await this.buildPopEntryHash({
        prevHash,
        streamPrevHash,
        auditHash,
        grant,
        claimer,
        periodIndex,
        issuedAt,
      });
      const entryHashHex = bytesToHex(entryHash);

      await this.ctx.storage.put(globalKey, entryHashHex);
      await this.ctx.storage.put(streamKey, entryHashHex);
      await this.ctx.storage.put(`pop_chain:history:${new Date().toISOString()}:${entryHashHex}`, {
        eventId,
        confirmationCode,
        receiptId: ticketReceipt.receiptId,
        receiptHash: ticketReceipt.receiptHash,
        anchorEntryHash: auditAnchor.entry_hash,
        grant: grantRaw,
        claimer: claimerRaw,
        periodIndex: periodIndex.toString(),
        prevHash: prevHashHex,
        streamPrevHash: streamPrevHashHex,
        auditHash: auditHashHex,
        entryHash: entryHashHex,
        issuedAt: Number(issuedAt),
      });

      const message = this.buildPopProofMessage({
        grant,
        claimer,
        periodIndex,
        prevHash,
        streamPrevHash,
        auditHash,
        entryHash,
        issuedAt,
      });
      const signature = nacl.sign.detached(message, signer.secretKey);

      return {
        signerPubkey: signer.signerPubkey,
        messageBase64: encodeBase64(message),
        signatureBase64: encodeBase64(signature),
        auditHash: auditHashHex,
        prevHash: prevHashHex,
        streamPrevHash: streamPrevHashHex,
        entryHash: entryHashHex,
        issuedAt: Number(issuedAt),
      };
    });

    this.popProofLock = task.then(() => { }, () => { });
    return task;
  }

  private extractBearerToken(request: Request): string | null {
    const authHeader = request.headers.get('Authorization') ?? '';
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    const token = match?.[1]?.trim() ?? '';
    return token || null;
  }

  private parseAdminCodeRecord(code: string, raw: unknown): (AdminCodeRecord & { code: string }) | null {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const nameRaw = typeof obj.name === 'string' ? obj.name.trim() : '';
    const createdAtRaw = typeof obj.createdAt === 'string' ? obj.createdAt.trim() : '';
    const adminIdRaw = typeof obj.adminId === 'string' ? obj.adminId.trim() : '';
    const revokedAtRaw = typeof obj.revokedAt === 'string' ? obj.revokedAt.trim() : '';
    const revokedByRaw = typeof obj.revokedBy === 'string' ? obj.revokedBy.trim() : '';
    return {
      code,
      adminId: adminIdRaw || `legacy-${code.slice(0, 12)}`,
      name: nameRaw || 'Unknown Admin',
      createdAt: createdAtRaw || new Date(0).toISOString(),
      source: 'invite',
      revokedAt: revokedAtRaw || null,
      revokedBy: revokedByRaw || null,
    };
  }

  private async findAdminCodeByAdminId(adminId: string): Promise<string | null> {
    const needle = adminId.trim();
    if (!needle) return null;
    const rows = await this.ctx.storage.list({ prefix: ADMIN_CODE_PREFIX });
    for (const [key, value] of rows.entries()) {
      const code = key.slice(ADMIN_CODE_PREFIX.length);
      const parsed = this.parseAdminCodeRecord(code, value);
      if (!parsed) continue;
      if (parsed.adminId === needle) return code;
    }
    return null;
  }

  private operatorToEventOwner(operator: OperatorIdentity): EventOwnerRecord {
    return {
      adminId: operator.adminId,
      name: operator.name,
      source: operator.source,
      linkedAt: new Date().toISOString(),
    };
  }

  private async getEventOwnerRecord(eventId: string): Promise<EventOwnerRecord | null> {
    const raw = await this.ctx.storage.get(eventOwnerKey(eventId));
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const adminId = typeof obj.adminId === 'string' ? obj.adminId.trim() : '';
    if (!adminId) return null;
    const sourceRaw = typeof obj.source === 'string' ? obj.source.trim() : '';
    const source: EventOwnerRecord['source'] =
      sourceRaw === 'master' || sourceRaw === 'demo' || sourceRaw === 'invite'
        ? sourceRaw
        : 'invite';
    return {
      adminId,
      name: typeof obj.name === 'string' && obj.name.trim() ? obj.name.trim() : 'Unknown Admin',
      source,
      linkedAt: typeof obj.linkedAt === 'string' && obj.linkedAt.trim() ? obj.linkedAt.trim() : new Date(0).toISOString(),
    };
  }

  private async ensureOperatorCanAccessEvent(operator: OperatorIdentity, eventId: string): Promise<Response | null> {
    if (operator.role === 'master') {
      return null;
    }
    const owner = await this.getEventOwnerRecord(eventId);
    if (!owner || owner.adminId !== operator.adminId) {
      return Response.json({ error: 'forbidden' }, { status: 403 });
    }
    return null;
  }

  private getConfiguredMasterPassword(): string | null {
    const password = this.env.ADMIN_PASSWORD?.trim() ?? '';
    if (!password || password === DEFAULT_ADMIN_PASSWORD) return null;
    return password;
  }

  private isDefaultMasterPasswordConfigured(): boolean {
    const password = this.env.ADMIN_PASSWORD?.trim() ?? '';
    return password === DEFAULT_ADMIN_PASSWORD;
  }

  private getConfiguredDemoPassword(): string | null {
    const password = this.env.ADMIN_DEMO_PASSWORD?.trim() ?? '';
    return password || null;
  }

  private unauthorizedResponse(): Response {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  private serverConfigErrorResponse(): Response {
    return Response.json({ error: 'server configuration error' }, { status: 500 });
  }

  private insecureMasterPasswordResponse(): Response {
    return Response.json(
      {
        error: 'insecure admin password configuration',
        code: 'insecure_admin_password',
        detail: 'Replace ADMIN_PASSWORD placeholder value before using master-protected APIs.',
      },
      { status: 503 }
    );
  }

  private async authenticateOperator(
    request: Request
  ): Promise<OperatorIdentity | null> {
    const token = this.extractBearerToken(request);
    if (!token) return null;

    const masterPassword = this.getConfiguredMasterPassword();
    if (masterPassword && token === masterPassword) {
      return {
        role: 'master',
        source: 'master',
        token,
        adminId: 'master',
        name: 'Master Operator',
        actorId: 'master',
      };
    }

    const demoPassword = this.getConfiguredDemoPassword();
    if (demoPassword && token === demoPassword) {
      return {
        role: 'admin',
        source: 'demo',
        token,
        adminId: 'demo-admin',
        name: 'Demo Admin',
        actorId: 'admin:demo-admin',
      };
    }

    const adminDataRaw = await this.ctx.storage.get(adminCodeKey(token));
    const adminData = this.parseAdminCodeRecord(token, adminDataRaw);
    if (adminData && !adminData.revokedAt) {
      return {
        role: 'admin',
        source: 'invite',
        token,
        adminId: adminData.adminId,
        name: adminData.name,
        actorId: `admin:${adminData.adminId}`,
        code: token,
      };
    }

    return null;
  }

  private requireMasterAuthorization(request: Request): Response | null {
    if (this.isDefaultMasterPasswordConfigured()) {
      return this.insecureMasterPasswordResponse();
    }
    const masterPassword = this.getConfiguredMasterPassword();
    if (!masterPassword) {
      return this.serverConfigErrorResponse();
    }
    const token = this.extractBearerToken(request);
    if (!token || token !== masterPassword) {
      return this.unauthorizedResponse();
    }
    return null;
  }

  private async requireAdminAuthorization(request: Request): Promise<Response | null> {
    const operator = await this.authenticateOperator(request);
    if (!operator) {
      return this.unauthorizedResponse();
    }
    return null;
  }

  private isAdminProtectedSchoolRoute(path: string, method: string): boolean {
    const normalizedMethod = method.toUpperCase();
    if (normalizedMethod === 'POST' && path === '/v1/school/events') return true;
    if (normalizedMethod === 'POST' && /^\/v1\/school\/events\/[^/]+\/close$/.test(path)) return true;
    if (normalizedMethod === 'GET' && /^\/v1\/school\/events\/[^/]+\/claimants$/.test(path)) return true;
    return false;
  }

  async appendAuditLog(event: string, actor: AuditActor, data: unknown, eventId: string): Promise<AuditEvent> {
    // Serialize globally so a single hash chain can cover all API logs.
    const task = this.auditLock.then(async () => {
      const ts = new Date().toISOString();
      const globalPrevHash = (await this.ctx.storage.get<string>(AUDIT_LAST_HASH_GLOBAL_KEY)) ?? 'GENESIS';
      const streamLastHashKey = `audit:lastHash:${eventId}`;
      const streamPrevHash = (await this.ctx.storage.get<string>(streamLastHashKey)) ?? 'GENESIS';

      const baseEntry = {
        ts,
        event,
        eventId,
        actor,
        data: (data as Record<string, unknown>) ?? {},
        prev_hash: globalPrevHash,
        stream_prev_hash: streamPrevHash,
      };

      const entry_hash = await sha256Hex(canonicalize(baseEntry));
      const fullEntry: AuditEvent = { ...baseEntry, entry_hash };

      const immutableReceipt = await persistImmutableAuditEntry({
        entry: fullEntry,
        mode: this.getAuditImmutableMode(),
        source: 'school-store',
        bindings: {
          AUDIT_LOGS: this.env.AUDIT_LOGS,
          AUDIT_INDEX: this.env.AUDIT_INDEX,
          AUDIT_IMMUTABLE_INGEST_URL: this.env.AUDIT_IMMUTABLE_INGEST_URL,
          AUDIT_IMMUTABLE_INGEST_TOKEN: this.env.AUDIT_IMMUTABLE_INGEST_TOKEN,
          AUDIT_IMMUTABLE_FETCH_TIMEOUT_MS: this.env.AUDIT_IMMUTABLE_FETCH_TIMEOUT_MS,
        },
      });
      if (immutableReceipt) {
        fullEntry.immutable = immutableReceipt;
      }

      // Update both global and per-event stream chains.
      await this.ctx.storage.put(AUDIT_LAST_HASH_GLOBAL_KEY, entry_hash);
      await this.ctx.storage.put(streamLastHashKey, entry_hash);

      // Store history for Master Dashboard
      // Key format: audit_history:<timestamp>:<hash> to allow reverse chronological listing
      const historyKey = `audit_history:${ts}:${entry_hash}`;
      await this.ctx.storage.put(historyKey, fullEntry);
      await this.ctx.storage.put(auditEntryByHashKey(entry_hash), fullEntry);

      return fullEntry;
    });

    // Update lock for next caller, robust against failures.
    this.auditLock = task.then(() => { }, () => { });

    return task;
  }

  async getAuditLogs(): Promise<AuditEvent[]> {
    // List latest 50 logs (reverse order)
    const result = await this.ctx.storage.list({ prefix: AUDIT_HISTORY_PREFIX, limit: 50, reverse: true });
    return Array.from(result.values()) as AuditEvent[];
  }

  private getAuditStatus() {
    const mode = this.getAuditImmutableMode();
    const r2Configured = Boolean(this.env.AUDIT_LOGS);
    const kvConfigured = Boolean(this.env.AUDIT_INDEX);
    const ingestConfigured = Boolean(this.env.AUDIT_IMMUTABLE_INGEST_URL?.trim());
    const primaryImmutableSinkConfigured = r2Configured || ingestConfigured;
    const operationalReady = mode === 'off' ? true : primaryImmutableSinkConfigured;
    return {
      mode,
      failClosedForMutatingRequests: mode === 'required',
      operationalReady,
      primaryImmutableSinkConfigured,
      sinks: {
        r2Configured,
        kvConfigured,
        ingestConfigured,
      },
    };
  }

  private getRuntimeStatus(): RuntimeStatusReport {
    const auditStatus = this.getAuditStatus();
    const fairscaleStatus = this.getFairscaleStatus();
    const blockingIssues: string[] = [];
    const warnings: string[] = [];

    const adminPasswordConfigured = this.getConfiguredMasterPassword() !== null;
    if (!adminPasswordConfigured) {
      blockingIssues.push('ADMIN_PASSWORD is not configured or still uses the default placeholder');
    }

    const popEnforced = this.isOnchainPopEnforced();
    let popSignerConfigured = false;
    let popSignerPubkey: string | null = null;
    let popSignerError: string | null = null;
    try {
      const signer = this.getPopSigner();
      popSignerConfigured = signer !== null;
      popSignerPubkey = signer?.signerPubkey ?? null;
    } catch (err) {
      popSignerError = err instanceof Error ? err.message : String(err);
    }

    if (popEnforced && !popSignerConfigured) {
      if (popSignerError) {
        blockingIssues.push(`PoP signer configuration error: ${popSignerError}`);
      } else {
        blockingIssues.push('PoP signer is not configured');
      }
    }

    if (auditStatus.failClosedForMutatingRequests && !auditStatus.operationalReady) {
      blockingIssues.push('Audit immutable sink is not operational while AUDIT_IMMUTABLE_MODE=required');
    }
    if (fairscaleStatus.enabled && fairscaleStatus.failClosed && !fairscaleStatus.operationalReady) {
      blockingIssues.push('FairScale is enabled in fail-closed mode but FAIRSCALE_BASE_URL is not configured');
    } else if (fairscaleStatus.enabled && !fairscaleStatus.operationalReady) {
      warnings.push('FairScale is enabled but FAIRSCALE_BASE_URL is not configured (fail-open mode)');
    }

    const corsOrigin = this.env.CORS_ORIGIN?.trim() ?? '';
    if (!corsOrigin) {
      warnings.push('CORS_ORIGIN is not set (default origin policy will be used)');
    } else if (corsOrigin === 'https://instant-grant-core.dev') {
      warnings.push('CORS_ORIGIN is still default; replace with your production Pages/custom domain');
    }

    return {
      ready: blockingIssues.length === 0,
      checkedAt: new Date().toISOString(),
      checks: {
        adminPasswordConfigured,
        popEnforced,
        popSignerConfigured,
        popSignerPubkey,
        popSignerError,
        auditMode: auditStatus.mode,
        auditOperationalReady: auditStatus.operationalReady,
        auditPrimarySinkConfigured: auditStatus.primaryImmutableSinkConfigured,
        fairscaleEnabled: fairscaleStatus.enabled,
        fairscaleOperationalReady: fairscaleStatus.operationalReady,
        fairscaleFailClosed: fairscaleStatus.failClosed,
        corsOrigin: corsOrigin || null,
      },
      blockingIssues,
      warnings,
    };
  }

  private buildAuditHashInput(entry: AuditEvent): Record<string, unknown> {
    const base: Record<string, unknown> = {
      ts: entry.ts,
      event: entry.event,
      eventId: entry.eventId,
      actor: entry.actor,
      data: entry.data,
      prev_hash: entry.prev_hash,
    };
    if (typeof entry.stream_prev_hash === 'string') {
      base.stream_prev_hash = entry.stream_prev_hash;
    }
    return base;
  }

  private buildImmutablePayload(entry: AuditEvent): string {
    const payloadEntry = {
      ...this.buildAuditHashInput(entry),
      entry_hash: entry.entry_hash,
    };
    return canonicalize({
      version: 1,
      source: IMMUTABLE_AUDIT_SOURCE,
      entry: payloadEntry,
    });
  }

  private async computeParticipationTicketReceiptHash(
    receipt: Omit<ParticipationTicketReceipt, 'receiptHash'>
  ): Promise<string> {
    return sha256Hex(canonicalize(receipt));
  }

  private async buildParticipationTicketReceipt(params: {
    eventId: string;
    subject: string;
    confirmationCode: string;
    auditEntry: AuditEvent;
  }): Promise<ParticipationTicketReceipt> {
    const { eventId, subject, confirmationCode, auditEntry } = params;
    const immutableSinks = (auditEntry.immutable?.sinks ?? []).map((sink) => ({
      sink: sink.sink,
      ref: sink.ref,
      at: sink.at,
    }));
    const receiptBase: Omit<ParticipationTicketReceipt, 'receiptHash'> = {
      version: PARTICIPATION_TICKET_RECEIPT_VERSION,
      type: PARTICIPATION_TICKET_RECEIPT_TYPE,
      receiptId: auditEntry.entry_hash,
      issuedAt: auditEntry.ts,
      confirmationCode,
      subjectCommitment: await sha256Hex(
        canonicalize({
          version: 1,
          eventId,
          subject,
        })
      ),
      verifyEndpoint: PARTICIPATION_TICKET_VERIFY_ENDPOINT,
      audit: {
        event: auditEntry.event,
        eventId: auditEntry.eventId,
        entryHash: auditEntry.entry_hash,
        prevHash: auditEntry.prev_hash,
        streamPrevHash: auditEntry.stream_prev_hash ?? 'GENESIS',
        immutableMode: auditEntry.immutable?.mode ?? 'off',
        immutablePayloadHash: auditEntry.immutable?.payload_hash ?? null,
        immutableSinks,
      },
    };

    const receiptHash = await this.computeParticipationTicketReceiptHash(receiptBase);
    return { ...receiptBase, receiptHash };
  }

  private parseParticipationTicketReceipt(raw: unknown): ParticipationTicketReceipt | null {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;

    if (obj.version !== PARTICIPATION_TICKET_RECEIPT_VERSION) return null;
    if (obj.type !== PARTICIPATION_TICKET_RECEIPT_TYPE) return null;

    const receiptId = this.normalizeStringField(obj.receiptId);
    const receiptHash = this.normalizeStringField(obj.receiptHash);
    const issuedAt = this.normalizeStringField(obj.issuedAt);
    const confirmationCode = this.normalizeStringField(obj.confirmationCode);
    const subjectCommitment = this.normalizeStringField(obj.subjectCommitment);
    const verifyEndpoint = this.normalizeStringField(obj.verifyEndpoint);
    if (!receiptId || !receiptHash || !issuedAt || !confirmationCode || !subjectCommitment || !verifyEndpoint) {
      return null;
    }
    if (!isHashHex(receiptId) || !isHashHex(receiptHash) || !isHashHex(subjectCommitment)) {
      return null;
    }

    const auditRaw = obj.audit;
    if (!auditRaw || typeof auditRaw !== 'object') return null;
    const auditObj = auditRaw as Record<string, unknown>;

    const event = this.normalizeStringField(auditObj.event);
    const eventId = this.normalizeStringField(auditObj.eventId);
    const entryHash = this.normalizeStringField(auditObj.entryHash);
    const prevHash = this.normalizeStringField(auditObj.prevHash);
    const streamPrevHash = this.normalizeStringField(auditObj.streamPrevHash);
    const immutableModeRaw = this.normalizeStringField(auditObj.immutableMode)?.toLowerCase() ?? '';
    if (immutableModeRaw !== 'off' && immutableModeRaw !== 'best_effort' && immutableModeRaw !== 'required') {
      return null;
    }
    const immutableMode: ParticipationTicketReceipt['audit']['immutableMode'] = immutableModeRaw;
    const immutablePayloadHashRaw = auditObj.immutablePayloadHash;
    const immutablePayloadHash =
      typeof immutablePayloadHashRaw === 'string' && immutablePayloadHashRaw.trim()
        ? immutablePayloadHashRaw.trim().toLowerCase()
        : immutablePayloadHashRaw === null
          ? null
          : null;

    if (!event || !eventId || !entryHash || !prevHash || !streamPrevHash) return null;
    if (!isHashHex(entryHash)) return null;
    if (!(prevHash === 'GENESIS' || isHashHex(prevHash))) return null;
    if (!(streamPrevHash === 'GENESIS' || isHashHex(streamPrevHash))) return null;
    if (!(immutablePayloadHash === null || isHashHex(immutablePayloadHash))) return null;

    const sinksRaw = auditObj.immutableSinks;
    if (!Array.isArray(sinksRaw)) return null;
    const immutableSinks: ParticipationTicketReceipt['audit']['immutableSinks'] = [];
    for (const sinkItem of sinksRaw) {
      if (!sinkItem || typeof sinkItem !== 'object') return null;
      const sinkObj = sinkItem as Record<string, unknown>;
      const sink = this.normalizeStringField(sinkObj.sink);
      const ref = this.normalizeStringField(sinkObj.ref);
      const at = this.normalizeStringField(sinkObj.at);
      if (!sink || !ref || !at) return null;
      if (sink !== 'r2_entry' && sink !== 'r2_stream' && sink !== 'kv_index' && sink !== 'immutable_ingest') {
        return null;
      }
      immutableSinks.push({ sink, ref, at });
    }

    return {
      version: PARTICIPATION_TICKET_RECEIPT_VERSION,
      type: PARTICIPATION_TICKET_RECEIPT_TYPE,
      receiptId: receiptId.toLowerCase(),
      receiptHash: receiptHash.toLowerCase(),
      issuedAt,
      confirmationCode,
      subjectCommitment: subjectCommitment.toLowerCase(),
      verifyEndpoint,
      audit: {
        event,
        eventId,
        entryHash: entryHash.toLowerCase(),
        prevHash: prevHash === 'GENESIS' ? 'GENESIS' : prevHash.toLowerCase(),
        streamPrevHash: streamPrevHash === 'GENESIS' ? 'GENESIS' : streamPrevHash.toLowerCase(),
        immutableMode,
        immutablePayloadHash,
        immutableSinks,
      },
    };
  }

  private async storeParticipationTicketReceipt(
    eventId: string,
    subject: string,
    receipt: ParticipationTicketReceipt
  ): Promise<void> {
    await this.ensureConfirmationCodeIndexed(eventId, subject, receipt.confirmationCode);
    await this.ctx.storage.put(ticketReceiptByCodeKey(eventId, receipt.confirmationCode), receipt);
    await this.ctx.storage.put(ticketReceiptBySubjectKey(eventId, subject), receipt);
  }

  private async getParticipationTicketReceipt(
    eventId: string,
    subject: string,
    confirmationCode: string
  ): Promise<ParticipationTicketReceipt | null> {
    const byCode = this.parseParticipationTicketReceipt(
      await this.ctx.storage.get(ticketReceiptByCodeKey(eventId, confirmationCode))
    );
    if (byCode) return byCode;

    const bySubject = this.parseParticipationTicketReceipt(
      await this.ctx.storage.get(ticketReceiptBySubjectKey(eventId, subject))
    );
    if (bySubject && bySubject.confirmationCode === confirmationCode) {
      return bySubject;
    }
    return null;
  }

  private parseConfirmationCodeIndexRecord(raw: unknown): ConfirmationCodeIndexRecord | null {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const code = this.normalizeStringField(obj.code);
    const eventId = this.normalizeStringField(obj.eventId);
    const subject = this.normalizeStringField(obj.subject);
    const issuedAt = this.normalizeStringField(obj.issuedAt);
    if (!code || !eventId || !subject || !issuedAt) return null;
    return { code, eventId, subject, issuedAt };
  }

  private parseUserIdIndexRecord(raw: unknown): UserIdIndexRecord | null {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const userId = this.normalizeStringField(obj.userId);
    const userIdHash = this.normalizeStringField(obj.userIdHash);
    const chainHash = this.normalizeStringField(obj.chainHash);
    const prevChainHash = this.normalizeStringField(obj.prevChainHash);
    const createdAt = this.normalizeStringField(obj.createdAt);
    if (!userId || !userIdHash || !chainHash || !prevChainHash || !createdAt) return null;
    if (!isHashHex(userIdHash) || !isHashHex(chainHash) || !isHashHex(prevChainHash)) return null;
    return { userId, userIdHash, chainHash, prevChainHash, createdAt };
  }

  private withConfirmationCodeLock<T>(taskFn: () => Promise<T>): Promise<T> {
    const task = this.confirmationCodeLock.then(taskFn);
    this.confirmationCodeLock = task.then(() => { }, () => { });
    return task;
  }

  private withUserIdRegistrationLock<T>(taskFn: () => Promise<T>): Promise<T> {
    const task = this.userIdRegistrationLock.then(taskFn);
    this.userIdRegistrationLock = task.then(() => { }, () => { });
    return task;
  }

  private validateUserIdForRegistration(userId: string): string | null {
    if (!userId) {
      return `userId required (${USER_ID_MIN_LENGTH}-${USER_ID_MAX_LENGTH})`;
    }
    if (!USER_ID_RE.test(userId)) {
      return 'userId must be 3-32 chars using a-z, 0-9, dot, underscore, hyphen';
    }
    return null;
  }

  private async registerUserWithUniqueId(params: {
    userId: string;
    displayName: string;
    pinHash: string;
  }): Promise<
    | { ok: true; userIdHash: string; chainHash: string; prevChainHash: string }
    | { ok: false }
  > {
    const userId = params.userId.trim();
    if (!userId) throw new Error('userId is required');

    return this.withUserIdRegistrationLock(async () => {
      const existingUser = await this.ctx.storage.get(userKey(userId));
      if (existingUser !== undefined) {
        return { ok: false };
      }

      const userIdHash = await hashString(`user-id:${userId}`);
      const indexKey = userIdIndexKey(userIdHash);
      const existingIndex = this.parseUserIdIndexRecord(
        await this.ctx.storage.get(indexKey)
      );
      if (existingIndex) {
        return { ok: false };
      }

      const lastChainHashRaw = await this.ctx.storage.get<string>(USER_ID_CHAIN_LAST_HASH_KEY);
      const prevChainHash =
        typeof lastChainHashRaw === 'string' && isHashHex(lastChainHashRaw)
          ? lastChainHashRaw.toLowerCase()
          : POP_HASH_GENESIS_HEX;
      const chainHash = await sha256Hex(
        canonicalize({
          version: 1,
          kind: 'user_id_register',
          userIdHash,
          prevChainHash,
        })
      );
      const createdAt = new Date().toISOString();

      await this.ctx.storage.put(userKey(userId), {
        pinHash: params.pinHash,
        displayName: params.displayName,
      });
      await this.ctx.storage.put(indexKey, {
        userId,
        userIdHash,
        chainHash,
        prevChainHash,
        createdAt,
      } satisfies UserIdIndexRecord);
      await this.ctx.storage.put(USER_ID_CHAIN_LAST_HASH_KEY, chainHash);

      return {
        ok: true,
        userIdHash,
        chainHash,
        prevChainHash,
      };
    });
  }

  private async reserveUniqueConfirmationCode(eventId: string, subject: string): Promise<string> {
    const normalizedEventId = eventId.trim();
    const normalizedSubject = subject.trim();
    if (!normalizedEventId || !normalizedSubject) {
      throw new Error('eventId and subject are required to issue confirmation code');
    }

    return this.withConfirmationCodeLock(async () => {
      const legacyReceiptRows = await this.ctx.storage.list({
        prefix: TICKET_RECEIPT_CODE_PREFIX,
        limit: CONFIRMATION_CODE_LEGACY_SCAN_LIMIT,
      });
      const legacyCodes = new Set<string>();
      for (const key of legacyReceiptRows.keys()) {
        const separatorAt = key.lastIndexOf(':');
        if (separatorAt < 0 || separatorAt >= key.length - 1) continue;
        const legacyCode = key.slice(separatorAt + 1).trim();
        if (legacyCode) legacyCodes.add(legacyCode);
      }

      for (let attempt = 0; attempt < CONFIRMATION_CODE_MAX_ATTEMPTS; attempt += 1) {
        const code = genConfirmationCode();
        if (legacyCodes.has(code)) continue;
        const key = confirmationCodeIndexKey(code);
        const existing = await this.ctx.storage.get(key);
        if (existing !== undefined) continue;
        await this.ctx.storage.put(key, {
          code,
          eventId: normalizedEventId,
          subject: normalizedSubject,
          issuedAt: new Date().toISOString(),
        } satisfies ConfirmationCodeIndexRecord);
        return code;
      }
      throw new Error('failed to generate unique confirmation code');
    });
  }

  private async ensureConfirmationCodeIndexed(
    eventId: string,
    subject: string,
    confirmationCode: string
  ): Promise<void> {
    const code = confirmationCode.trim();
    const normalizedEventId = eventId.trim();
    const normalizedSubject = subject.trim();
    if (!code || !normalizedEventId || !normalizedSubject) return;

    await this.withConfirmationCodeLock(async () => {
      const key = confirmationCodeIndexKey(code);
      const existing = await this.ctx.storage.get(key);
      if (existing !== undefined) {
        return;
      }
      await this.ctx.storage.put(key, {
        code,
        eventId: normalizedEventId,
        subject: normalizedSubject,
        issuedAt: new Date().toISOString(),
      } satisfies ConfirmationCodeIndexRecord);
    });
  }

  private async releaseReservedConfirmationCode(
    eventId: string,
    subject: string,
    confirmationCode: string
  ): Promise<void> {
    const code = confirmationCode.trim();
    const normalizedEventId = eventId.trim();
    const normalizedSubject = subject.trim();
    if (!code || !normalizedEventId || !normalizedSubject) return;

    await this.withConfirmationCodeLock(async () => {
      const key = confirmationCodeIndexKey(code);
      const existing = this.parseConfirmationCodeIndexRecord(
        await this.ctx.storage.get(key)
      );
      if (!existing) return;
      if (existing.eventId !== normalizedEventId || existing.subject !== normalizedSubject) return;
      await this.ctx.storage.delete(key);
    });
  }

  private async getAuditEntryByHash(entryHash: string): Promise<AuditEvent | null> {
    const hash = entryHash.trim().toLowerCase();
    if (!isHashHex(hash)) return null;

    const direct = await this.ctx.storage.get(auditEntryByHashKey(hash));
    if (direct && typeof direct === 'object' && typeof (direct as { entry_hash?: unknown }).entry_hash === 'string') {
      return direct as AuditEvent;
    }

    const rows = await this.ctx.storage.list({
      prefix: AUDIT_HISTORY_PREFIX,
      reverse: true,
      limit: AUDIT_ENTRY_SCAN_LIMIT,
    });
    for (const value of rows.values()) {
      if (!value || typeof value !== 'object') continue;
      const entry = value as AuditEvent;
      if (typeof entry.entry_hash === 'string' && entry.entry_hash.toLowerCase() === hash) {
        return entry;
      }
    }
    return null;
  }

  private sinkSignatureSet(sinks: Array<{ sink: string; ref: string }>): Set<string> {
    const out = new Set<string>();
    for (const sink of sinks) {
      out.add(`${sink.sink}|${sink.ref}`);
    }
    return out;
  }

  private async verifyParticipationTicketReceipt(
    receipt: ParticipationTicketReceipt
  ): Promise<ParticipationTicketReceiptVerification> {
    const issues: ParticipationTicketReceiptValidationIssue[] = [];
    const checks: ParticipationTicketReceiptVerification['checks'] = {
      receiptHashValid: false,
      entryExists: false,
      entryHashValid: false,
      confirmationCodeMatches: false,
      eventIdMatches: false,
      globalChainLinkValid: false,
      streamChainLinkValid: false,
      immutablePayloadHashMatches: false,
      immutableSinksMatch: false,
    };

    const hashInput: Omit<ParticipationTicketReceipt, 'receiptHash'> = {
      version: receipt.version,
      type: receipt.type,
      receiptId: receipt.receiptId,
      issuedAt: receipt.issuedAt,
      confirmationCode: receipt.confirmationCode,
      subjectCommitment: receipt.subjectCommitment,
      verifyEndpoint: receipt.verifyEndpoint,
      audit: {
        event: receipt.audit.event,
        eventId: receipt.audit.eventId,
        entryHash: receipt.audit.entryHash,
        prevHash: receipt.audit.prevHash,
        streamPrevHash: receipt.audit.streamPrevHash,
        immutableMode: receipt.audit.immutableMode,
        immutablePayloadHash: receipt.audit.immutablePayloadHash,
        immutableSinks: receipt.audit.immutableSinks.map((sink) => ({
          sink: sink.sink,
          ref: sink.ref,
          at: sink.at,
        })),
      },
    };
    const expectedReceiptHash = await this.computeParticipationTicketReceiptHash(hashInput);
    checks.receiptHashValid = expectedReceiptHash === receipt.receiptHash;
    if (!checks.receiptHashValid) {
      issues.push({
        code: 'receipt_hash_mismatch',
        message: 'receiptHash does not match canonical receipt payload',
        field: 'receiptHash',
      });
    }

    const entry = await this.getAuditEntryByHash(receipt.audit.entryHash);
    checks.entryExists = entry !== null;
    if (!entry) {
      issues.push({
        code: 'entry_not_found',
        message: 'audit entry referenced by receipt is not found in history',
        field: 'audit.entryHash',
      });
      return {
        ok: false,
        checkedAt: new Date().toISOString(),
        receiptId: receipt.receiptId,
        eventId: receipt.audit.eventId,
        confirmationCode: receipt.confirmationCode,
        checks,
        issues,
        proof: {
          entryHash: receipt.audit.entryHash,
          prevHash: receipt.audit.prevHash,
          streamPrevHash: receipt.audit.streamPrevHash,
          immutablePayloadHash: receipt.audit.immutablePayloadHash,
          immutableSinks: receipt.audit.immutableSinks.map((sink) => ({
            sink: sink.sink,
            ref: sink.ref,
            at: sink.at,
          })),
        },
      };
    }

    const recomputedEntryHash = await sha256Hex(canonicalize(this.buildAuditHashInput(entry)));
    checks.entryHashValid = recomputedEntryHash === entry.entry_hash && entry.entry_hash === receipt.audit.entryHash;
    if (!checks.entryHashValid) {
      issues.push({
        code: 'entry_hash_mismatch',
        message: 'audit entry hash mismatch',
        field: 'audit.entryHash',
      });
    }
    if (receipt.receiptId !== receipt.audit.entryHash || receipt.receiptId !== entry.entry_hash) {
      issues.push({
        code: 'receipt_id_mismatch',
        message: 'receiptId does not match the referenced audit entry hash',
        field: 'receiptId',
      });
    }

    const entryConfirmationCode = this.normalizeStringField((entry.data as Record<string, unknown>).confirmationCode);
    checks.confirmationCodeMatches = entryConfirmationCode === receipt.confirmationCode;
    if (!checks.confirmationCodeMatches) {
      issues.push({
        code: 'confirmation_code_mismatch',
        message: 'confirmationCode does not match the audit entry payload',
        field: 'confirmationCode',
      });
    }

    checks.eventIdMatches =
      entry.eventId === receipt.audit.eventId &&
      entry.eventId.length > 0;
    if (!checks.eventIdMatches) {
      issues.push({
        code: 'event_id_mismatch',
        message: 'eventId does not match the audit entry',
        field: 'eventId',
      });
    }

    if (entry.prev_hash !== receipt.audit.prevHash) {
      issues.push({
        code: 'prev_hash_mismatch',
        message: 'prevHash in receipt does not match the audit entry',
        field: 'audit.prevHash',
      });
    }
    if ((entry.stream_prev_hash ?? 'GENESIS') !== receipt.audit.streamPrevHash) {
      issues.push({
        code: 'stream_prev_hash_mismatch',
        message: 'streamPrevHash in receipt does not match the audit entry',
        field: 'audit.streamPrevHash',
      });
    }

    if (entry.prev_hash === 'GENESIS') {
      checks.globalChainLinkValid = true;
    } else {
      const prevEntry = await this.getAuditEntryByHash(entry.prev_hash);
      checks.globalChainLinkValid = prevEntry !== null && prevEntry.entry_hash === entry.prev_hash;
      if (!checks.globalChainLinkValid) {
        issues.push({
          code: 'global_chain_link_missing',
          message: 'global predecessor entry is missing or invalid',
          field: 'audit.prevHash',
        });
      }
    }

    const streamPrevHash = entry.stream_prev_hash ?? 'GENESIS';
    if (streamPrevHash === 'GENESIS') {
      checks.streamChainLinkValid = true;
    } else {
      const prevStreamEntry = await this.getAuditEntryByHash(streamPrevHash);
      checks.streamChainLinkValid =
        prevStreamEntry !== null &&
        prevStreamEntry.entry_hash === streamPrevHash &&
        prevStreamEntry.eventId === entry.eventId;
      if (!checks.streamChainLinkValid) {
        issues.push({
          code: 'stream_chain_link_missing',
          message: 'event stream predecessor entry is missing or invalid',
          field: 'audit.streamPrevHash',
        });
      }
    }

    const recomputedImmutablePayloadHash = await sha256Hex(this.buildImmutablePayload(entry));
    const entryImmutablePayloadHash = entry.immutable?.payload_hash ?? null;
    const receiptImmutablePayloadHash = receipt.audit.immutablePayloadHash ?? null;
    checks.immutablePayloadHashMatches =
      (entryImmutablePayloadHash === null && receiptImmutablePayloadHash === null) ||
      (entryImmutablePayloadHash === recomputedImmutablePayloadHash &&
        receiptImmutablePayloadHash === recomputedImmutablePayloadHash);
    if (!checks.immutablePayloadHashMatches) {
      issues.push({
        code: 'immutable_payload_hash_mismatch',
        message: 'immutable payload hash mismatch between receipt and audit entry',
        field: 'audit.immutablePayloadHash',
      });
    }

    const entrySinkSet = this.sinkSignatureSet(
      (entry.immutable?.sinks ?? []).map((sink) => ({ sink: sink.sink, ref: sink.ref }))
    );
    const receiptSinkSet = this.sinkSignatureSet(
      receipt.audit.immutableSinks.map((sink) => ({ sink: sink.sink, ref: sink.ref }))
    );
    checks.immutableSinksMatch =
      entrySinkSet.size === receiptSinkSet.size &&
      Array.from(receiptSinkSet.values()).every((sig) => entrySinkSet.has(sig));
    if (!checks.immutableSinksMatch) {
      issues.push({
        code: 'immutable_sinks_mismatch',
        message: 'immutable sink references mismatch between receipt and audit entry',
        field: 'audit.immutableSinks',
      });
    }

    const entryImmutableMode = entry.immutable?.mode ?? 'off';
    if (entryImmutableMode !== receipt.audit.immutableMode) {
      issues.push({
        code: 'immutable_mode_mismatch',
        message: 'immutable mode mismatch between receipt and audit entry',
        field: 'audit.immutableMode',
      });
    }

    return {
      ok: issues.length === 0,
      checkedAt: new Date().toISOString(),
      receiptId: receipt.receiptId,
      eventId: receipt.audit.eventId,
      confirmationCode: receipt.confirmationCode,
      checks,
      issues,
      proof: {
        entryHash: entry.entry_hash,
        prevHash: entry.prev_hash,
        streamPrevHash: entry.stream_prev_hash ?? 'GENESIS',
        immutablePayloadHash: entry.immutable?.payload_hash ?? null,
        immutableSinks: (entry.immutable?.sinks ?? []).map((sink) => ({
          sink: sink.sink,
          ref: sink.ref,
          at: sink.at,
        })),
      },
    };
  }

  private async verifyAuditIntegrity(limit: number, verifyImmutable: boolean): Promise<AuditIntegrityReport> {
    const mode = this.getAuditImmutableMode();
    const shouldVerifyImmutable = verifyImmutable && mode !== 'off';
    const issues: AuditIntegrityIssue[] = [];
    const warningSet = new Set<string>();

    const rows = await this.ctx.storage.list({ prefix: AUDIT_HISTORY_PREFIX, limit, reverse: true });
    const entries = Array.from(rows.values()) as AuditEvent[];

    const validEntries: AuditEvent[] = [];

    for (const entry of entries) {
      if (!entry || typeof entry !== 'object' || typeof entry.entry_hash !== 'string') {
        issues.push({
          code: 'invalid_entry_shape',
          message: 'invalid audit history entry',
        });
        continue;
      }
      if (typeof entry.eventId !== 'string' || !entry.eventId) {
        issues.push({
          code: 'invalid_entry_shape',
          message: 'invalid eventId in audit history entry',
          entryHash: entry.entry_hash,
        });
        continue;
      }
      if (typeof entry.prev_hash !== 'string' || !entry.prev_hash) {
        issues.push({
          code: 'invalid_entry_shape',
          message: 'invalid prev_hash in audit history entry',
          entryHash: entry.entry_hash,
          eventId: entry.eventId,
        });
        continue;
      }

      const recomputedEntryHash = await sha256Hex(canonicalize(this.buildAuditHashInput(entry)));
      if (recomputedEntryHash !== entry.entry_hash) {
        issues.push({
          code: 'entry_hash_mismatch',
          message: 'entry hash mismatch',
          entryHash: entry.entry_hash,
          eventId: entry.eventId,
        });
      }

      validEntries.push(entry);

      if (shouldVerifyImmutable) {
        if (!entry.immutable) {
          issues.push({
            code: 'immutable_receipt_missing',
            message: 'immutable receipt is missing',
            entryHash: entry.entry_hash,
            eventId: entry.eventId,
          });
        } else {
          const payload = this.buildImmutablePayload(entry);
          const payloadHash = await sha256Hex(payload);
          if (entry.immutable.payload_hash !== payloadHash) {
            issues.push({
              code: 'immutable_payload_hash_mismatch',
              message: 'immutable payload hash mismatch',
              entryHash: entry.entry_hash,
              eventId: entry.eventId,
            });
          }

          const hasPrimarySink = entry.immutable.sinks.some(
            (sink) => sink.sink === 'r2_entry' || sink.sink === 'immutable_ingest'
          );
          if (!hasPrimarySink) {
            issues.push({
              code: 'immutable_primary_sink_missing',
              message: 'immutable receipt has no accepted primary sink',
              entryHash: entry.entry_hash,
              eventId: entry.eventId,
            });
          }

          const r2Refs = entry.immutable.sinks.filter((sink) => sink.sink === 'r2_entry');
          if (r2Refs.length > 0) {
            if (!this.env.AUDIT_LOGS) {
              warningSet.add('AUDIT_LOGS binding is not configured, skipped R2 object checks');
            } else {
              for (const sink of r2Refs) {
                const objectBody = await this.env.AUDIT_LOGS.get(sink.ref);
                if (!objectBody) {
                  issues.push({
                    code: 'immutable_r2_object_missing',
                    message: 'immutable R2 object is missing',
                    entryHash: entry.entry_hash,
                    eventId: entry.eventId,
                    ref: sink.ref,
                  });
                  continue;
                }
                const objectText = await objectBody.text();
                if (objectText !== payload) {
                  issues.push({
                    code: 'immutable_r2_object_mismatch',
                    message: 'immutable R2 object content mismatch',
                    entryHash: entry.entry_hash,
                    eventId: entry.eventId,
                    ref: sink.ref,
                  });
                }
              }
            }
          }
        }
      }

    }

    const entriesByHash = new Map<string, AuditEvent>();
    const globalChildCount = new Map<string, number>();
    const globalExternalPrevRefs: AuditEvent[] = [];

    for (const entry of validEntries) {
      if (entriesByHash.has(entry.entry_hash)) {
        issues.push({
          code: 'global_chain_break',
          message: 'duplicate entry_hash detected in audit window',
          entryHash: entry.entry_hash,
          eventId: entry.eventId,
        });
      }
      entriesByHash.set(entry.entry_hash, entry);
    }

    for (const entry of validEntries) {
      if (entry.prev_hash === 'GENESIS') continue;
      if (entriesByHash.has(entry.prev_hash)) {
        globalChildCount.set(entry.prev_hash, (globalChildCount.get(entry.prev_hash) ?? 0) + 1);
      } else {
        globalExternalPrevRefs.push(entry);
      }
    }

    for (const [entryHash, childCount] of globalChildCount.entries()) {
      if (childCount > 1) {
        const entry = entriesByHash.get(entryHash);
        issues.push({
          code: 'global_chain_break',
          message: 'multiple newer entries point to the same global predecessor',
          entryHash,
          eventId: entry?.eventId,
        });
      }
    }

    if (globalExternalPrevRefs.length > 1) {
      issues.push({
        code: 'global_chain_break',
        message: 'multiple entries point outside of current global audit window',
        entryHash: globalExternalPrevRefs[0]?.entry_hash,
        eventId: globalExternalPrevRefs[0]?.eventId,
      });
    }

    const globalHeads = validEntries.filter((entry) => !globalChildCount.has(entry.entry_hash));
    if (validEntries.length > 0 && globalHeads.length !== 1) {
      issues.push({
        code: 'global_chain_break',
        message: 'global chain must have exactly one head in audit window',
      });
    }

    const globalHead = globalHeads[0] ?? null;
    let oldestInWindowEntry: AuditEvent | null = null;

    if (globalHead) {
      const visited = new Set<string>();
      let current: AuditEvent | null = globalHead;
      while (current) {
        if (visited.has(current.entry_hash)) {
          issues.push({
            code: 'global_chain_break',
            message: 'cycle detected in global chain',
            entryHash: current.entry_hash,
            eventId: current.eventId,
          });
          break;
        }
        visited.add(current.entry_hash);
        oldestInWindowEntry = current;

        if (current.prev_hash === 'GENESIS') break;
        current = entriesByHash.get(current.prev_hash) ?? null;
      }

      if (visited.size !== validEntries.length) {
        issues.push({
          code: 'global_chain_break',
          message: 'global chain is disconnected within audit window',
          entryHash: globalHead.entry_hash,
          eventId: globalHead.eventId,
        });
      }
    }

    const entriesByEvent = new Map<string, AuditEvent[]>();
    for (const entry of validEntries) {
      const bucket = entriesByEvent.get(entry.eventId);
      if (bucket) bucket.push(entry);
      else entriesByEvent.set(entry.eventId, [entry]);
    }

    for (const [eventId, streamEntries] of entriesByEvent.entries()) {
      const streamByHash = new Map<string, AuditEvent>();
      const streamChildCount = new Map<string, number>();
      const streamExternalPrevRefs: AuditEvent[] = [];

      for (const entry of streamEntries) {
        if (streamByHash.has(entry.entry_hash)) {
          issues.push({
            code: 'stream_chain_break',
            message: 'duplicate entry_hash detected in event stream',
            entryHash: entry.entry_hash,
            eventId,
          });
        }
        streamByHash.set(entry.entry_hash, entry);
      }

      for (const entry of streamEntries) {
        const streamPrevHash = entry.stream_prev_hash ?? 'GENESIS';
        if (streamPrevHash === 'GENESIS') continue;
        if (streamByHash.has(streamPrevHash)) {
          streamChildCount.set(streamPrevHash, (streamChildCount.get(streamPrevHash) ?? 0) + 1);
        } else {
          streamExternalPrevRefs.push(entry);
        }
      }

      for (const [entryHash, childCount] of streamChildCount.entries()) {
        if (childCount > 1) {
          issues.push({
            code: 'stream_chain_break',
            message: 'multiple newer stream entries point to the same predecessor',
            entryHash,
            eventId,
          });
        }
      }

      if (streamExternalPrevRefs.length > 1) {
        issues.push({
          code: 'stream_chain_break',
          message: 'multiple stream entries point outside of current event window',
          entryHash: streamExternalPrevRefs[0]?.entry_hash,
          eventId,
        });
      }

      const streamHeads = streamEntries.filter((entry) => !streamChildCount.has(entry.entry_hash));
      if (streamHeads.length !== 1) {
        issues.push({
          code: 'stream_chain_break',
          message: 'event stream must have exactly one head in audit window',
          entryHash: streamHeads[0]?.entry_hash,
          eventId,
        });
        continue;
      }

      const visited = new Set<string>();
      let current: AuditEvent | null = streamHeads[0];
      while (current) {
        if (visited.has(current.entry_hash)) {
          issues.push({
            code: 'stream_chain_break',
            message: 'cycle detected in event stream chain',
            entryHash: current.entry_hash,
            eventId,
          });
          break;
        }
        visited.add(current.entry_hash);
        const streamPrevHash: string = typeof current.stream_prev_hash === 'string'
          ? current.stream_prev_hash
          : 'GENESIS';
        if (streamPrevHash === 'GENESIS') break;
        current = streamByHash.get(streamPrevHash) ?? null;
      }

      if (visited.size !== streamEntries.length) {
        issues.push({
          code: 'stream_chain_break',
          message: 'event stream chain is disconnected within audit window',
          entryHash: streamHeads[0].entry_hash,
          eventId,
        });
      }
    }

    return {
      ok: issues.length === 0,
      mode,
      checked: entries.length,
      limit,
      globalHead: globalHead?.entry_hash ?? null,
      oldestInWindow: oldestInWindowEntry?.entry_hash ?? null,
      verifyImmutable: shouldVerifyImmutable,
      issues,
      warnings: Array.from(warningSet.values()),
      inspectedAt: new Date().toISOString(),
    };
  }

  private isApiPath(path: string): boolean {
    return path.startsWith('/api/') || path.startsWith('/v1/school/');
  }

  private routeTemplate(path: string): string {
    if (/^\/v1\/school\/events\/[^/]+\/close$/.test(path)) return '/v1/school/events/:eventId/close';
    if (/^\/v1\/school\/events\/[^/]+\/claimants$/.test(path)) return '/v1/school/events/:eventId/claimants';
    if (/^\/v1\/school\/events\/[^/]+$/.test(path)) return '/v1/school/events/:eventId';
    if (/^\/api\/events\/[^/]+\/claim$/.test(path)) return '/api/events/:eventId/claim';
    return path;
  }

  private eventIdForAudit(path: string, body: unknown): string {
    const schoolEventPath = path.match(/^\/v1\/school\/events\/([^/]+)/);
    if (schoolEventPath?.[1]) return schoolEventPath[1];

    const userEventPath = path.match(/^\/api\/events\/([^/]+)\/claim$/);
    if (userEventPath?.[1]) return userEventPath[1];

    if (body && typeof body === 'object' && 'eventId' in body) {
      const raw = (body as { eventId?: unknown }).eventId;
      if (typeof raw === 'string' && raw.trim()) return raw.trim();
    }

    return 'system';
  }

  private maskActorId(id: string): string {
    const trimmed = id.trim();
    if (!trimmed) return 'unknown';
    if (trimmed.length <= 8) return trimmed;
    return `${trimmed.slice(0, 4)}...${trimmed.slice(-4)}`;
  }

  private normalizeStringField(raw: unknown): string | null {
    if (typeof raw !== 'string') return null;
    const normalized = raw.trim();
    return normalized || null;
  }

  private normalizeUserId(raw: unknown): string {
    if (typeof raw !== 'string') return '';
    return raw.trim().toLowerCase();
  }

  private normalizeNumberField(raw: unknown): number | null {
    if (typeof raw === 'number' && Number.isFinite(raw)) return raw;
    if (typeof raw === 'string' && raw.trim() && /^-?\d+(\.\d+)?$/.test(raw.trim())) {
      const parsed = Number(raw.trim());
      return Number.isFinite(parsed) ? parsed : null;
    }
    return null;
  }

  private normalizeTransferParty(raw: unknown): TransferParty | null {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const type = this.normalizeStringField(obj.type);
    const id = this.normalizeStringField(obj.id);
    if (!type || !id) return null;
    return { type, id };
  }

  private buildClaimTransferPayload(params: {
    eventId: string;
    event: {
      solanaAuthority?: unknown;
      solanaMint?: unknown;
      ticketTokenAmount?: unknown;
    };
    recipient: TransferParty;
    txSignature?: unknown;
    receiptPubkey?: unknown;
  }): TransferAuditPayload {
    const senderId = this.normalizeStringField(params.event.solanaAuthority) ?? `grant:${params.eventId}`;
    const txSignature = this.normalizeStringField(params.txSignature);
    return {
      mode: txSignature ? 'onchain' : 'offchain',
      asset: 'ticket_token',
      amount: this.normalizeNumberField(params.event.ticketTokenAmount),
      mint: this.normalizeStringField(params.event.solanaMint),
      txSignature,
      receiptPubkey: this.normalizeStringField(params.receiptPubkey),
      sender: { type: 'grant_authority', id: senderId },
      recipient: params.recipient,
    };
  }

  private parseStructuredTransferPayload(data: Record<string, unknown>): TransferAuditPayload | null {
    const transferRaw = data.transfer;
    if (!transferRaw || typeof transferRaw !== 'object') return null;
    const transferObj = transferRaw as Record<string, unknown>;

    const sender = this.normalizeTransferParty(transferObj.sender);
    const recipient = this.normalizeTransferParty(transferObj.recipient);
    if (!sender || !recipient) return null;

    const modeRaw = this.normalizeStringField(transferObj.mode);
    const mode = modeRaw === 'onchain' ? 'onchain' : 'offchain';
    const assetRaw = this.normalizeStringField(transferObj.asset);
    const asset = assetRaw === 'ticket_token' ? 'ticket_token' : 'ticket_token';
    const amount = this.normalizeNumberField(transferObj.amount);

    return {
      mode,
      asset,
      amount,
      mint: this.normalizeStringField(transferObj.mint),
      txSignature: this.normalizeStringField(transferObj.txSignature),
      receiptPubkey: this.normalizeStringField(transferObj.receiptPubkey),
      sender,
      recipient,
    };
  }

  private parseLegacyTransferPayload(entry: AuditEvent): TransferAuditPayload | null {
    const data = (entry.data ?? {}) as Record<string, unknown>;
    const senderId =
      this.normalizeStringField(data.solanaAuthority) ??
      this.normalizeStringField(data.authority) ??
      `grant:${entry.eventId}`;
    const mint = this.normalizeStringField(data.solanaMint);
    const amount = this.normalizeNumberField(data.ticketTokenAmount);
    const txSignature = this.normalizeStringField(data.txSignature);
    const receiptPubkey = this.normalizeStringField(data.receiptPubkey);
    const mode: 'onchain' | 'offchain' = txSignature ? 'onchain' : 'offchain';

    if (entry.event === 'WALLET_CLAIM') {
      const walletAddress = this.normalizeStringField(data.walletAddress);
      const joinToken = this.normalizeStringField(data.joinToken);
      const recipientId = walletAddress ?? joinToken;
      if (!recipientId) return null;
      return {
        mode,
        asset: 'ticket_token',
        amount,
        mint,
        txSignature,
        receiptPubkey,
        sender: { type: 'grant_authority', id: senderId },
        recipient: { type: walletAddress ? 'wallet' : 'join_token', id: recipientId },
      };
    }

    if (entry.event === 'USER_CLAIM') {
      const walletAddress = this.normalizeStringField(data.walletAddress);
      const userId =
        this.normalizeStringField(data.userId) ??
        this.normalizeStringField(entry.actor?.id) ??
        'unknown';
      return {
        mode,
        asset: 'ticket_token',
        amount,
        mint,
        txSignature,
        receiptPubkey,
        sender: { type: 'grant_authority', id: senderId },
        recipient: { type: walletAddress ? 'wallet' : 'user', id: walletAddress ?? userId },
      };
    }

    return null;
  }

  private extractTransferPii(data: Record<string, unknown>): Record<string, string> | undefined {
    const out: Record<string, string> = {};
    const piiRaw = data.pii;
    if (piiRaw && typeof piiRaw === 'object') {
      for (const [key, value] of Object.entries(piiRaw as Record<string, unknown>)) {
        const normalized = this.normalizeStringField(value);
        if (normalized) out[key] = normalized;
      }
    }

    const legacyKeys = ['walletAddress', 'joinToken', 'userId', 'displayName'];
    for (const key of legacyKeys) {
      const normalized = this.normalizeStringField(data[key]);
      if (normalized) out[key] = normalized;
    }

    return Object.keys(out).length > 0 ? out : undefined;
  }

  private toTransferLogView(entry: AuditEvent): TransferLogView | null {
    const data = (entry.data ?? {}) as Record<string, unknown>;
    const transfer =
      this.parseStructuredTransferPayload(data) ??
      this.parseLegacyTransferPayload(entry);
    if (!transfer) return null;

    return {
      ts: entry.ts,
      event: entry.event,
      eventId: entry.eventId,
      entryHash: entry.entry_hash,
      prevHash: entry.prev_hash,
      streamPrevHash: entry.stream_prev_hash ?? 'GENESIS',
      transfer,
      pii: this.extractTransferPii(data),
    };
  }

  private applyTransferRoleView(view: TransferLogView, role: TransferLogRoleView): TransferLogView {
    if (role === 'master') {
      return view;
    }

    return {
      ...view,
      pii: undefined,
    };
  }

  private async getTransferLogs(role: TransferLogRoleView, options: {
    limit: number;
    eventId?: string | null;
  }): Promise<TransferLogView[]> {
    const eventIdFilter = options.eventId?.trim() || null;
    const scanLimit = Math.min(1000, Math.max(options.limit * 6, options.limit));
    const rows = await this.ctx.storage.list({
      prefix: AUDIT_HISTORY_PREFIX,
      limit: scanLimit,
      reverse: true,
    });

    const items: TransferLogView[] = [];
    for (const value of rows.values()) {
      if (!value || typeof value !== 'object') continue;
      const entry = value as AuditEvent;
      const view = this.toTransferLogView(entry);
      if (!view) continue;
      if (eventIdFilter && view.eventId !== eventIdFilter) continue;
      items.push(this.applyTransferRoleView(view, role));
      if (items.length >= options.limit) break;
    }
    return items;
  }

  private async getLatestUserTransferSnapshots(
    userId: string,
    eventIds: Set<string>
  ): Promise<Map<string, UserTicketTransferSnapshot>> {
    const normalizedUserId = this.normalizeUserId(userId);
    const snapshots = new Map<string, UserTicketTransferSnapshot>();
    if (!normalizedUserId || eventIds.size === 0) return snapshots;

    const rows = await this.ctx.storage.list({
      prefix: AUDIT_HISTORY_PREFIX,
      limit: AUDIT_ENTRY_SCAN_LIMIT,
      reverse: true,
    });

    for (const value of rows.values()) {
      if (snapshots.size >= eventIds.size) break;
      if (!value || typeof value !== 'object') continue;
      const entry = value as AuditEvent;
      if (entry.event !== 'USER_CLAIM') continue;
      if (!eventIds.has(entry.eventId)) continue;
      if (snapshots.has(entry.eventId)) continue;

      const view = this.toTransferLogView(entry);
      if (!view) continue;

      const piiUserId = this.normalizeUserId(view.pii?.userId);
      const recipientUserId =
        view.transfer.recipient.type === 'user'
          ? this.normalizeUserId(view.transfer.recipient.id)
          : '';
      if (piiUserId !== normalizedUserId && recipientUserId !== normalizedUserId) continue;

      snapshots.set(entry.eventId, {
        txSignature: view.transfer.txSignature,
        receiptPubkey: view.transfer.receiptPubkey,
        mint: view.transfer.mint,
      });
    }

    return snapshots;
  }

  private async buildUserTicketSyncItems(userId: string): Promise<UserTicketSyncItem[]> {
    const normalizedUserId = this.normalizeUserId(userId);
    if (!normalizedUserId) return [];

    const claims = await this.store.getClaimsBySubject(normalizedUserId);
    if (claims.length === 0) return [];

    const eventIds = new Set(claims.map((claim) => claim.eventId));
    const [events, transferSnapshots] = await Promise.all([
      this.store.getEvents(),
      this.getLatestUserTransferSnapshots(normalizedUserId, eventIds),
    ]);
    const eventById = new Map(events.map((event) => [event.id, event]));

    const tickets: UserTicketSyncItem[] = [];
    for (const claim of claims) {
      const event = eventById.get(claim.eventId);
      const snapshot = transferSnapshots.get(claim.eventId);
      const receipt = this.parseParticipationTicketReceipt(
        await this.ctx.storage.get(ticketReceiptBySubjectKey(claim.eventId, normalizedUserId))
      );
      const mint = snapshot?.mint ?? this.normalizeStringField(event?.solanaMint);
      const confirmationCode = claim.confirmationCode ?? receipt?.confirmationCode;

      tickets.push({
        eventId: claim.eventId,
        eventName: event?.title ?? claim.eventId,
        claimedAt: claim.claimedAt,
        ...(confirmationCode ? { confirmationCode } : {}),
        ...(receipt?.receiptId ? { auditReceiptId: receipt.receiptId } : {}),
        ...(receipt?.receiptHash ? { auditReceiptHash: receipt.receiptHash } : {}),
        ...(snapshot?.txSignature ? { txSignature: snapshot.txSignature } : {}),
        ...(snapshot?.receiptPubkey ? { receiptPubkey: snapshot.receiptPubkey } : {}),
        ...(mint ? { mint } : {}),
      });
    }

    tickets.sort((a, b) => b.claimedAt - a.claimedAt);
    return tickets;
  }

  private async getMasterAdminDisclosures(options: {
    includeRevoked: boolean;
    transferLimit: number;
  }): Promise<MasterAdminDisclosuresResponse> {
    const adminRows = await this.ctx.storage.list({ prefix: ADMIN_CODE_PREFIX });
    const parsedAdmins: Array<AdminCodeRecord & { code: string }> = [];
    for (const [key, value] of adminRows.entries()) {
      const code = key.slice(ADMIN_CODE_PREFIX.length);
      const parsed = this.parseAdminCodeRecord(code, value);
      if (!parsed) continue;
      if (!options.includeRevoked && parsed.revokedAt) continue;
      parsedAdmins.push(parsed);
    }
    parsedAdmins.sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    type RelatedUserAccumulator = {
      key: string;
      userId: string | null;
      displayName: string | null;
      walletAddress: string | null;
      joinToken: string | null;
      recipientType: string;
      recipientId: string;
      claims: MasterAdminDisclosureUserClaim[];
    };

    type AdminAccumulator = {
      profile: Omit<MasterAdminDisclosure, 'relatedUsers'>;
      relatedUsers: Map<string, RelatedUserAccumulator>;
    };

    const admins = new Map<string, AdminAccumulator>();
    const adminNameIndex = new Map<string, string[]>();
    for (const admin of parsedAdmins) {
      const normalizedName = admin.name.trim().toLowerCase();
      if (normalizedName) {
        const bucket = adminNameIndex.get(normalizedName);
        if (bucket) bucket.push(admin.adminId);
        else adminNameIndex.set(normalizedName, [admin.adminId]);
      }
      admins.set(admin.adminId, {
        profile: {
          adminId: admin.adminId,
          code: admin.code,
          name: admin.name,
          createdAt: admin.createdAt,
          status: admin.revokedAt ? 'revoked' : 'active',
          revokedAt: admin.revokedAt,
          events: [],
          relatedTransferCount: 0,
        },
        relatedUsers: new Map<string, RelatedUserAccumulator>(),
      });
    }

    const events = await this.store.getEvents();
    const eventOwnerById = new Map<string, string>();
    const eventTitleById = new Map<string, string>();

    for (const event of events) {
      eventTitleById.set(event.id, event.title);
      const explicitOwner = await this.getEventOwnerRecord(event.id);
      let ownerAdminId: string | null = explicitOwner?.adminId ?? null;
      let ownerSource: MasterAdminDisclosureEvent['ownerSource'] = explicitOwner
        ? explicitOwner.source
        : 'inferred';

      if (!ownerAdminId) {
        const normalizedHost = event.host.trim().toLowerCase();
        const matchedAdminIds = adminNameIndex.get(normalizedHost) ?? [];
        if (matchedAdminIds.length === 1) {
          ownerAdminId = matchedAdminIds[0];
          ownerSource = 'inferred';
        }
      }

      if (!ownerAdminId) continue;
      const adminBucket = admins.get(ownerAdminId);
      if (!adminBucket) continue;

      eventOwnerById.set(event.id, ownerAdminId);
      adminBucket.profile.events.push({
        id: event.id,
        title: event.title,
        datetime: event.datetime,
        host: event.host,
        state: event.state ?? 'published',
        claimedCount: event.claimedCount ?? 0,
        ownerSource,
      });
    }

    const transfers = await this.getTransferLogs('master', { limit: options.transferLimit });
    for (const entry of transfers) {
      const ownerAdminId = eventOwnerById.get(entry.eventId);
      if (!ownerAdminId) continue;
      const adminBucket = admins.get(ownerAdminId);
      if (!adminBucket) continue;

      adminBucket.profile.relatedTransferCount += 1;

      const pii = entry.pii ?? {};
      const userId = this.normalizeStringField(pii.userId);
      const displayName = this.normalizeStringField(pii.displayName);
      const walletAddress =
        this.normalizeStringField(pii.walletAddress) ??
        (entry.transfer.recipient.type === 'wallet' ? entry.transfer.recipient.id : null);
      const joinToken =
        this.normalizeStringField(pii.joinToken) ??
        (entry.transfer.recipient.type === 'join_token' ? entry.transfer.recipient.id : null);
      const key =
        userId ? `user:${userId}` :
          walletAddress ? `wallet:${walletAddress}` :
            joinToken ? `join:${joinToken}` :
              `recipient:${entry.transfer.recipient.type}:${entry.transfer.recipient.id}`;

      const existing = adminBucket.relatedUsers.get(key);
      const row: RelatedUserAccumulator = existing ?? {
        key,
        userId: userId ?? null,
        displayName: displayName ?? null,
        walletAddress: walletAddress ?? null,
        joinToken: joinToken ?? null,
        recipientType: entry.transfer.recipient.type,
        recipientId: entry.transfer.recipient.id,
        claims: [],
      };
      if (!row.userId && userId) row.userId = userId;
      if (!row.displayName && displayName) row.displayName = displayName;
      if (!row.walletAddress && walletAddress) row.walletAddress = walletAddress;
      if (!row.joinToken && joinToken) row.joinToken = joinToken;
      row.claims.push({
        ts: entry.ts,
        eventId: entry.eventId,
        eventTitle: eventTitleById.get(entry.eventId) ?? null,
        transfer: entry.transfer,
        pii: entry.pii,
      });
      adminBucket.relatedUsers.set(key, row);
    }

    const disclosureList: MasterAdminDisclosure[] = Array.from(admins.values()).map((bucket) => {
      const relatedUsers: MasterAdminDisclosureUser[] = Array.from(bucket.relatedUsers.values())
        .map((user) => {
          const eventIds = Array.from(new Set(user.claims.map((claim) => claim.eventId)));
          return {
            key: user.key,
            userId: user.userId,
            displayName: user.displayName,
            walletAddress: user.walletAddress,
            joinToken: user.joinToken,
            recipientType: user.recipientType,
            recipientId: user.recipientId,
            eventIds,
            claims: user.claims,
          };
        })
        .sort((a, b) => {
          const left = a.claims[0]?.ts ?? '';
          const right = b.claims[0]?.ts ?? '';
          return right.localeCompare(left);
        });
      const eventsSorted = [...bucket.profile.events].sort((a, b) => a.id.localeCompare(b.id));
      return {
        ...bucket.profile,
        events: eventsSorted,
        relatedUsers,
      };
    });

    disclosureList.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return {
      checkedAt: new Date().toISOString(),
      strictLevel: 'master_full',
      includeRevoked: options.includeRevoked,
      transferLimit: options.transferLimit,
      admins: disclosureList,
    };
  }

  private normalizeSearchText(value: string): string {
    return value.toLowerCase().replace(/\s+/g, ' ').trim();
  }

  private tokenizeSearchTerms(value: string): string[] {
    const normalized = this.normalizeSearchText(value);
    if (!normalized) return [];
    const terms = normalized
      .split(/[\s,.;:/\\|()[\]{}<>!"'`~@#$%^&*+=?\-]+/g)
      .map((part) => part.trim().slice(0, 64))
      .filter((part) => part.length > 0);
    return Array.from(new Set(terms));
  }

  private addDocIndexToken(index: Map<string, number[]>, token: string, docIndex: number): void {
    if (!token) return;
    const bucket = index.get(token);
    if (!bucket) {
      index.set(token, [docIndex]);
      return;
    }
    if (bucket[bucket.length - 1] !== docIndex) {
      bucket.push(docIndex);
    }
  }

  private buildMasterSearchDocuments(admins: MasterAdminDisclosure[]): MasterSearchIndexDocument[] {
    const docs: MasterSearchIndexDocument[] = [];
    const shorten = (value?: string | null, start = 8, end = 8) => {
      if (!value) return '-';
      if (value.length <= start + end + 3) return value;
      return `${value.slice(0, start)}...${value.slice(-end)}`;
    };

    for (const admin of admins) {
      const adminDoc: MasterSearchIndexDocument = {
        id: `admin:${admin.adminId}`,
        kind: 'admin',
        title: `${admin.name} (${admin.status})`,
        subtitle: `adminId=${admin.adminId} code=${admin.code}`,
        detail: `events=${admin.events.length} relatedUsers=${admin.relatedUsers.length} transfers=${admin.relatedTransferCount}`,
        searchText: this.normalizeSearchText([
          admin.adminId,
          admin.code,
          admin.name,
          admin.status,
          admin.createdAt,
          admin.revokedAt ?? '',
          String(admin.events.length),
          String(admin.relatedUsers.length),
          String(admin.relatedTransferCount),
        ].join(' ')),
      };
      docs.push(adminDoc);

      for (const event of admin.events) {
        docs.push({
          id: `event:${admin.adminId}:${event.id}`,
          kind: 'event',
          title: `${event.title} (${event.id})`,
          subtitle: `admin=${admin.name} owner=${event.ownerSource}`,
          detail: `state=${event.state} claims=${event.claimedCount} host=${event.host}`,
          searchText: this.normalizeSearchText([
            admin.name,
            admin.adminId,
            event.id,
            event.title,
            event.host,
            event.state,
            event.ownerSource,
            event.datetime,
            String(event.claimedCount),
          ].join(' ')),
        });
      }

      for (const user of admin.relatedUsers) {
        docs.push({
          id: `user:${admin.adminId}:${user.key}`,
          kind: 'user',
          title: `${user.displayName ?? '-'} / userId=${user.userId ?? '-'}`,
          subtitle: `admin=${admin.name} wallet=${user.walletAddress ?? '-'} joinToken=${user.joinToken ?? '-'}`,
          detail: `recipient=${user.recipientType}:${user.recipientId} events=${user.eventIds.join(', ') || '-'}`,
          searchText: this.normalizeSearchText([
            admin.name,
            admin.adminId,
            user.key,
            user.userId ?? '',
            user.displayName ?? '',
            user.walletAddress ?? '',
            user.joinToken ?? '',
            user.recipientType,
            user.recipientId,
            user.eventIds.join(' '),
          ].join(' ')),
        });

        for (let i = 0; i < user.claims.length; i += 1) {
          const claim = user.claims[i];
          docs.push({
            id: `claim:${admin.adminId}:${user.key}:${claim.eventId}:${i}`,
            kind: 'claim',
            title: `${claim.eventId} (${claim.eventTitle ?? '-'})`,
            subtitle: `admin=${admin.name} user=${user.displayName ?? user.userId ?? user.recipientId}`,
            detail: `transfer=${claim.transfer.sender.id} -> ${claim.transfer.recipient.id} tx=${shorten(claim.transfer.txSignature)}`,
            searchText: this.normalizeSearchText([
              admin.name,
              admin.adminId,
              user.userId ?? '',
              user.displayName ?? '',
              user.walletAddress ?? '',
              user.joinToken ?? '',
              claim.eventId,
              claim.eventTitle ?? '',
              claim.ts,
              claim.transfer.sender.type,
              claim.transfer.sender.id,
              claim.transfer.recipient.type,
              claim.transfer.recipient.id,
              claim.transfer.txSignature ?? '',
              claim.transfer.receiptPubkey ?? '',
              claim.transfer.mint ?? '',
              ...(claim.pii ? Object.values(claim.pii) : []),
            ].join(' ')),
          });
        }
      }
    }
    return docs;
  }

  private buildMasterSearchTokenIndex(docs: MasterSearchIndexDocument[]): Map<string, number[]> {
    const tokenToDocIds = new Map<string, number[]>();
    for (let docIndex = 0; docIndex < docs.length; docIndex += 1) {
      const doc = docs[docIndex];
      const terms = this.tokenizeSearchTerms(`${doc.title} ${doc.subtitle} ${doc.detail} ${doc.searchText}`);
      const prefixedTokens = new Set<string>();
      for (const term of terms) {
        if (!term) continue;
        prefixedTokens.add(term);
        if (term.length <= 1) continue;
        const maxPrefix = Math.min(24, term.length);
        for (let len = 2; len <= maxPrefix; len += 1) {
          prefixedTokens.add(term.slice(0, len));
        }
      }
      for (const token of prefixedTokens) {
        this.addDocIndexToken(tokenToDocIds, token, docIndex);
      }
    }
    return tokenToDocIds;
  }

  private getSqlStorageOrNull(): SqlStorage | null {
    const candidate = (this.ctx.storage as { sql?: unknown }).sql;
    if (!candidate || typeof (candidate as { exec?: unknown }).exec !== 'function') {
      return null;
    }
    return candidate as SqlStorage;
  }

  private ensureMasterSearchSqlTables(sql: SqlStorage): void {
    if (this.masterSearchSqlTablesReady) return;
    sql.exec(`
      CREATE TABLE IF NOT EXISTS master_search_index_meta (
        index_key TEXT PRIMARY KEY,
        built_at TEXT NOT NULL,
        built_at_ms INTEGER NOT NULL,
        doc_count INTEGER NOT NULL,
        token_count INTEGER NOT NULL
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS master_search_docs (
        index_key TEXT NOT NULL,
        doc_id INTEGER NOT NULL,
        result_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        title TEXT NOT NULL,
        subtitle TEXT NOT NULL,
        detail TEXT NOT NULL,
        search_text TEXT NOT NULL,
        PRIMARY KEY (index_key, doc_id)
      )
    `);
    sql.exec(`
      CREATE TABLE IF NOT EXISTS master_search_tokens (
        index_key TEXT NOT NULL,
        token TEXT NOT NULL,
        doc_id INTEGER NOT NULL,
        PRIMARY KEY (index_key, token, doc_id)
      )
    `);
    sql.exec('CREATE INDEX IF NOT EXISTS idx_master_search_tokens_lookup ON master_search_tokens(index_key, token, doc_id)');
    sql.exec('CREATE INDEX IF NOT EXISTS idx_master_search_docs_lookup ON master_search_docs(index_key, doc_id)');
    this.masterSearchSqlTablesReady = true;
  }

  private readMasterSearchSqlMeta(sql: SqlStorage, key: string): MasterSearchSqlIndexMeta | null {
    const row = sql
      .exec<{ built_at: string | null; built_at_ms: number | null }>(
        'SELECT built_at, built_at_ms FROM master_search_index_meta WHERE index_key = ? LIMIT 1',
        key
      )
      .toArray()[0];
    if (!row) return null;

    const builtAtMsCandidate =
      typeof row.built_at_ms === 'number'
        ? row.built_at_ms
        : Number.parseInt(String(row.built_at_ms ?? ''), 10);
    const builtAtMs = Number.isFinite(builtAtMsCandidate)
      ? Math.max(0, Math.trunc(builtAtMsCandidate))
      : Date.now();
    const builtAt =
      typeof row.built_at === 'string' && row.built_at.trim()
        ? row.built_at.trim()
        : new Date(builtAtMs).toISOString();
    return { key, builtAtMs, builtAt };
  }

  private pruneMasterSearchSqlIndexes(sql: SqlStorage): void {
    const staleRows = sql
      .exec<{ index_key: string }>(
        'SELECT index_key FROM master_search_index_meta ORDER BY built_at_ms DESC LIMIT 100 OFFSET ?',
        MASTER_SEARCH_SQL_KEEP_KEYS
      )
      .toArray();

    for (const row of staleRows) {
      const staleKey = typeof row.index_key === 'string' ? row.index_key.trim() : '';
      if (!staleKey) continue;
      sql.exec('DELETE FROM master_search_tokens WHERE index_key = ?', staleKey);
      sql.exec('DELETE FROM master_search_docs WHERE index_key = ?', staleKey);
      sql.exec('DELETE FROM master_search_index_meta WHERE index_key = ?', staleKey);
    }
  }

  private persistMasterSearchSqlIndex(sql: SqlStorage, params: {
    key: string;
    builtAt: string;
    builtAtMs: number;
    docs: MasterSearchIndexDocument[];
    tokenToDocIds: Map<string, number[]>;
  }): void {
    sql.exec('DELETE FROM master_search_tokens WHERE index_key = ?', params.key);
    sql.exec('DELETE FROM master_search_docs WHERE index_key = ?', params.key);
    sql.exec('DELETE FROM master_search_index_meta WHERE index_key = ?', params.key);

    for (let docId = 0; docId < params.docs.length; docId += 1) {
      const doc = params.docs[docId];
      sql.exec(
        'INSERT INTO master_search_docs(index_key, doc_id, result_id, kind, title, subtitle, detail, search_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        params.key,
        docId,
        doc.id,
        doc.kind,
        doc.title,
        doc.subtitle,
        doc.detail,
        doc.searchText
      );
    }

    let tokenCount = 0;
    for (const [token, docIds] of params.tokenToDocIds.entries()) {
      if (!token) continue;
      for (const docId of docIds) {
        sql.exec(
          'INSERT INTO master_search_tokens(index_key, token, doc_id) VALUES (?, ?, ?)',
          params.key,
          token,
          docId
        );
        tokenCount += 1;
      }
    }

    sql.exec(
      'INSERT INTO master_search_index_meta(index_key, built_at, built_at_ms, doc_count, token_count) VALUES (?, ?, ?, ?, ?)',
      params.key,
      params.builtAt,
      params.builtAtMs,
      params.docs.length,
      tokenCount
    );
    this.pruneMasterSearchSqlIndexes(sql);
  }

  private parseMasterSearchSqlDocId(raw: unknown): number | null {
    const numeric =
      typeof raw === 'number' && Number.isFinite(raw)
        ? raw
        : Number.parseInt(String(raw ?? ''), 10);
    if (!Number.isFinite(numeric)) return null;
    const asInt = Math.trunc(numeric);
    return asInt >= 0 ? asInt : null;
  }

  private getMasterSearchSqlTermDocIds(sql: SqlStorage, indexKey: string, term: string): number[] {
    const exactRows = sql
      .exec<{ doc_id: number }>(
        'SELECT doc_id FROM master_search_tokens WHERE index_key = ? AND token = ? ORDER BY doc_id LIMIT ?',
        indexKey,
        term,
        MASTER_SEARCH_SQL_TERM_DOC_LIMIT
      )
      .toArray();
    const exact = exactRows
      .map((row) => this.parseMasterSearchSqlDocId(row.doc_id))
      .filter((value): value is number => value !== null);
    if (exact.length > 0) return exact;

    const likeRows = sql
      .exec<{ doc_id: number }>(
        'SELECT doc_id FROM master_search_docs WHERE index_key = ? AND search_text LIKE ? ORDER BY doc_id LIMIT ?',
        indexKey,
        `%${term}%`,
        MASTER_SEARCH_SQL_TERM_DOC_LIMIT
      )
      .toArray();
    return likeRows
      .map((row) => this.parseMasterSearchSqlDocId(row.doc_id))
      .filter((value): value is number => value !== null);
  }

  private fetchMasterSearchSqlDocuments(sql: SqlStorage, indexKey: string, docIds: number[]): Array<{
    docId: number;
    doc: MasterSearchIndexDocument;
  }> {
    if (docIds.length === 0) return [];
    const out: Array<{ docId: number; doc: MasterSearchIndexDocument }> = [];
    for (let i = 0; i < docIds.length; i += MASTER_SEARCH_SQL_DOC_CHUNK_SIZE) {
      const chunk = docIds.slice(i, i + MASTER_SEARCH_SQL_DOC_CHUNK_SIZE);
      if (chunk.length === 0) continue;
      const placeholders = chunk.map(() => '?').join(', ');
      const rows = sql
        .exec<{
          doc_id: number;
          result_id: string;
          kind: string;
          title: string;
          subtitle: string;
          detail: string;
          search_text: string;
        }>(
          `SELECT doc_id, result_id, kind, title, subtitle, detail, search_text FROM master_search_docs WHERE index_key = ? AND doc_id IN (${placeholders})`,
          indexKey,
          ...chunk
        )
        .toArray();
      for (const row of rows) {
        const docId = this.parseMasterSearchSqlDocId(row.doc_id);
        if (docId === null) continue;
        const kindRaw = typeof row.kind === 'string' ? row.kind : '';
        const kind: MasterSearchKind =
          kindRaw === 'admin' || kindRaw === 'event' || kindRaw === 'user' || kindRaw === 'claim'
            ? kindRaw
            : 'admin';
        const resultId = typeof row.result_id === 'string' ? row.result_id : '';
        if (!resultId) continue;
        out.push({
          docId,
          doc: {
            id: resultId,
            kind,
            title: typeof row.title === 'string' ? row.title : '',
            subtitle: typeof row.subtitle === 'string' ? row.subtitle : '',
            detail: typeof row.detail === 'string' ? row.detail : '',
            searchText: typeof row.search_text === 'string' ? row.search_text : '',
          },
        });
      }
    }
    out.sort((a, b) => a.docId - b.docId);
    return out;
  }

  private searchMasterIndexSql(sql: SqlStorage, indexKey: string, query: string, limit: number): {
    total: number;
    items: MasterSearchResultItem[];
  } {
    const normalizedQuery = this.normalizeSearchText(query);
    if (!normalizedQuery) {
      return { total: 0, items: [] };
    }
    const terms = this.tokenizeSearchTerms(normalizedQuery);
    const targetTerms = terms.length > 0 ? terms : [normalizedQuery];

    let candidateIds: Set<number> | null = null;
    for (const term of targetTerms) {
      const ids = this.getMasterSearchSqlTermDocIds(sql, indexKey, term);
      const termSet = new Set(ids);
      if (candidateIds === null) {
        candidateIds = termSet;
      } else {
        for (const docId of Array.from(candidateIds)) {
          if (!termSet.has(docId)) candidateIds.delete(docId);
        }
      }
      if (candidateIds.size === 0) break;
      if (candidateIds.size > MASTER_SEARCH_SQL_TERM_DOC_LIMIT) {
        candidateIds = new Set(Array.from(candidateIds).slice(0, MASTER_SEARCH_SQL_TERM_DOC_LIMIT));
      }
    }
    if (!candidateIds || candidateIds.size === 0) {
      return { total: 0, items: [] };
    }

    const docs = this.fetchMasterSearchSqlDocuments(sql, indexKey, Array.from(candidateIds));
    if (docs.length === 0) {
      return { total: 0, items: [] };
    }

    const ranked = docs.map(({ docId, doc }) => {
      const title = doc.title.toLowerCase();
      const subtitle = doc.subtitle.toLowerCase();
      const detail = doc.detail.toLowerCase();
      let score = 0;
      if (doc.searchText.includes(normalizedQuery)) score += 12;
      if (title.includes(normalizedQuery)) score += 8;
      if (subtitle.includes(normalizedQuery)) score += 4;
      if (detail.includes(normalizedQuery)) score += 2;
      for (const term of targetTerms) {
        if (title.includes(term)) score += 3;
        if (subtitle.includes(term)) score += 2;
        if (doc.searchText.includes(term)) score += 1;
      }
      return { docId, score, doc };
    });

    ranked.sort((a, b) => b.score - a.score || a.docId - b.docId);
    const items = ranked.slice(0, limit).map(({ doc }) => ({
      id: doc.id,
      kind: doc.kind,
      title: doc.title,
      subtitle: doc.subtitle,
      detail: doc.detail,
    }));
    return {
      total: ranked.length,
      items,
    };
  }

  private async ensureMasterSearchSqlIndex(options: {
    includeRevoked: boolean;
    transferLimit: number;
  }): Promise<MasterSearchSqlIndexMeta | null> {
    const sql = this.getSqlStorageOrNull();
    if (!sql) return null;
    this.ensureMasterSearchSqlTables(sql);

    const auditHead = readHashHex(await this.ctx.storage.get<string>(AUDIT_LAST_HASH_GLOBAL_KEY));
    const key = `${auditHead}|${options.includeRevoked ? '1' : '0'}|${options.transferLimit}`;

    if (this.masterSearchSqlMetaCache?.key === key) {
      return this.masterSearchSqlMetaCache;
    }

    const existing = this.readMasterSearchSqlMeta(sql, key);
    if (existing) {
      this.masterSearchSqlMetaCache = existing;
      return existing;
    }

    const disclosure = await this.getMasterAdminDisclosures(options);
    const docs = this.buildMasterSearchDocuments(disclosure.admins);
    const tokenToDocIds = this.buildMasterSearchTokenIndex(docs);
    const builtAtMs = Date.now();
    const builtAt = new Date(builtAtMs).toISOString();
    this.persistMasterSearchSqlIndex(sql, {
      key,
      builtAt,
      builtAtMs,
      docs,
      tokenToDocIds,
    });

    this.masterSearchIndexCache = {
      key,
      builtAtMs,
      builtAt,
      docs,
      tokenToDocIds,
    };
    const meta = { key, builtAtMs, builtAt };
    this.masterSearchSqlMetaCache = meta;
    return meta;
  }

  private async getMasterSearchIndex(options: {
    includeRevoked: boolean;
    transferLimit: number;
  }): Promise<MasterSearchIndexCache> {
    const auditHead = readHashHex(await this.ctx.storage.get<string>(AUDIT_LAST_HASH_GLOBAL_KEY));
    const cacheKey = `${auditHead}|${options.includeRevoked ? '1' : '0'}|${options.transferLimit}`;
    const now = Date.now();

    if (
      this.masterSearchIndexCache &&
      this.masterSearchIndexCache.key === cacheKey &&
      now - this.masterSearchIndexCache.builtAtMs <= MASTER_SEARCH_INDEX_TTL_MS
    ) {
      return this.masterSearchIndexCache;
    }

    const disclosure = await this.getMasterAdminDisclosures(options);
    const docs = this.buildMasterSearchDocuments(disclosure.admins);
    const tokenToDocIds = this.buildMasterSearchTokenIndex(docs);
    const nextCache: MasterSearchIndexCache = {
      key: cacheKey,
      builtAtMs: now,
      builtAt: new Date(now).toISOString(),
      docs,
      tokenToDocIds,
    };
    this.masterSearchIndexCache = nextCache;
    return nextCache;
  }

  private searchMasterIndex(index: MasterSearchIndexCache, query: string, limit: number): {
    total: number;
    items: MasterSearchResultItem[];
  } {
    const normalizedQuery = this.normalizeSearchText(query);
    if (!normalizedQuery) {
      return { total: 0, items: [] };
    }
    const terms = this.tokenizeSearchTerms(normalizedQuery);
    const targetTerms = terms.length > 0 ? terms : [normalizedQuery];

    let candidateIds: Set<number> | null = null;
    for (const term of targetTerms) {
      const indexed = index.tokenToDocIds.get(term) ?? [];
      let matches = indexed;
      if (matches.length === 0) {
        const scanned: number[] = [];
        for (let i = 0; i < index.docs.length; i += 1) {
          if (index.docs[i].searchText.includes(term)) {
            scanned.push(i);
          }
        }
        matches = scanned;
      }

      const matchSet = new Set(matches);
      if (candidateIds === null) {
        candidateIds = matchSet;
      } else {
        for (const docId of Array.from(candidateIds)) {
          if (!matchSet.has(docId)) candidateIds.delete(docId);
        }
      }
      if (candidateIds.size === 0) {
        break;
      }
    }

    if (!candidateIds || candidateIds.size === 0) {
      return { total: 0, items: [] };
    }

    const ranked = Array.from(candidateIds).map((docIndex) => {
      const doc = index.docs[docIndex];
      const title = doc.title.toLowerCase();
      const subtitle = doc.subtitle.toLowerCase();
      const detail = doc.detail.toLowerCase();
      let score = 0;
      if (doc.searchText.includes(normalizedQuery)) score += 12;
      if (title.includes(normalizedQuery)) score += 8;
      if (subtitle.includes(normalizedQuery)) score += 4;
      if (detail.includes(normalizedQuery)) score += 2;
      for (const term of targetTerms) {
        if (title.includes(term)) score += 3;
        if (subtitle.includes(term)) score += 2;
        if (doc.searchText.includes(term)) score += 1;
      }
      return { docIndex, score };
    });

    ranked.sort((a, b) => b.score - a.score || a.docIndex - b.docIndex);
    const items = ranked.slice(0, limit).map(({ docIndex }) => {
      const doc = index.docs[docIndex];
      return {
        id: doc.id,
        kind: doc.kind,
        title: doc.title,
        subtitle: doc.subtitle,
        detail: doc.detail,
      };
    });
    return {
      total: ranked.length,
      items,
    };
  }

  private actorForAudit(path: string, request: Request, body: unknown): AuditActor {
    if (path === '/api/audit/receipts/verify' || path === '/api/audit/receipts/verify-code') {
      return { type: 'auditor', id: 'public' };
    }

    if (path.startsWith('/api/admin/') || path.startsWith('/api/master/')) {
      const hasAuth = Boolean(this.extractBearerToken(request));
      return { type: 'operator', id: hasAuth ? 'authenticated' : 'anonymous' };
    }

    if (this.isAdminProtectedSchoolRoute(path, request.method)) {
      const hasAuth = Boolean(this.extractBearerToken(request));
      return { type: 'operator', id: hasAuth ? 'authenticated' : 'anonymous' };
    }

    if (path === '/v1/school/claims') {
      const payload = body as { walletAddress?: unknown; joinToken?: unknown } | undefined;
      const wallet = typeof payload?.walletAddress === 'string' ? payload.walletAddress : '';
      const joinToken = typeof payload?.joinToken === 'string' ? payload.joinToken : '';
      const subject = wallet || joinToken;
      return { type: 'wallet', id: this.maskActorId(subject || 'unknown') };
    }

    if (
      path === '/api/users/register' ||
      path === '/api/auth/verify' ||
      path === '/api/users/tickets/sync' ||
      /^\/api\/events\/[^/]+\/claim$/.test(path)
    ) {
      const payload = body as { userId?: unknown } | undefined;
      const userId = this.normalizeUserId(payload?.userId);
      return { type: 'user', id: userId || 'anonymous' };
    }

    if (path.startsWith('/v1/school/')) {
      return { type: 'school', id: 'public-api' };
    }

    return { type: 'system', id: 'api' };
  }

  private isSensitiveKey(key: string): boolean {
    const lowered = key.toLowerCase();
    return (
      lowered.includes('password') ||
      lowered.includes('pin') ||
      lowered.includes('token') ||
      lowered.includes('authorization') ||
      lowered.includes('secret') ||
      lowered.includes('private') ||
      lowered === 'code' ||
      lowered.endsWith('_code')
    );
  }

  private sanitizeAuditValue(value: unknown, depth = 0): unknown {
    if (depth > AUDIT_MAX_DEPTH) return '[TRUNCATED_DEPTH]';
    if (value === null || value === undefined) return value;
    if (typeof value === 'string') {
      if (value.length > AUDIT_MAX_STRING) return `${value.slice(0, AUDIT_MAX_STRING)}...`;
      return value;
    }
    if (typeof value === 'number' || typeof value === 'boolean') return value;
    if (Array.isArray(value)) {
      return value.slice(0, AUDIT_MAX_ARRAY).map((item) => this.sanitizeAuditValue(item, depth + 1));
    }
    if (typeof value === 'object') {
      const obj = value as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      const keys = Object.keys(obj).slice(0, AUDIT_MAX_KEYS);
      for (const key of keys) {
        if (this.isSensitiveKey(key)) {
          out[key] = '[REDACTED]';
          continue;
        }
        out[key] = this.sanitizeAuditValue(obj[key], depth + 1);
      }
      return out;
    }
    return String(value);
  }

  private async requestBodyForAudit(request: Request): Promise<unknown> {
    const method = request.method.toUpperCase();
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) return undefined;

    const contentType = request.headers.get('content-type') ?? '';
    if (!contentType.toLowerCase().includes('application/json')) return undefined;

    try {
      return await request.clone().json();
    } catch {
      return { parseError: 'invalid_json' };
    }
  }

  private apiAuditEventName(method: string, route: string): string {
    const token = route
      .replace(/^\/+/, '')
      .replace(/[:]/g, '')
      .replace(/[^a-zA-Z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .toUpperCase();
    return `API_${method.toUpperCase()}_${token || 'ROOT'}`;
  }

  private async appendApiAuditTrail(
    request: Request,
    url: URL,
    path: string,
    response: Response,
    requestBody: unknown,
    startedAt: number,
    errorMessage?: string
  ): Promise<void> {
    if (!this.isApiPath(path) || request.method.toUpperCase() === 'OPTIONS') return;

    const route = this.routeTemplate(path);
    const event = this.apiAuditEventName(request.method, route);
    const actor = this.actorForAudit(path, request, requestBody);
    const eventId = this.eventIdForAudit(path, requestBody);

    const query: Record<string, string> = {};
    for (const [k, v] of url.searchParams.entries()) query[k] = v;
    const hasQuery = Object.keys(query).length > 0;

    const data: Record<string, unknown> = {
      route,
      method: request.method.toUpperCase(),
      status: response.status,
      statusClass: response.status >= 500 ? '5xx' : response.status >= 400 ? '4xx' : response.status >= 300 ? '3xx' : '2xx',
      durationMs: Date.now() - startedAt,
      hasAuthorization: Boolean(request.headers.get('Authorization')),
      origin: request.headers.get('origin') ?? '',
      requestBody: this.sanitizeAuditValue(requestBody),
      ...(hasQuery ? { query: this.sanitizeAuditValue(query) } : {}),
      ...(errorMessage ? { errorMessage } : {}),
    };

    try {
      await this.appendAuditLog(event, actor, data, eventId);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error('[audit] failed to append API audit trail', { event, path, message });
      if (this.isAuditFailClosed(path, request.method)) {
        throw new Error(`audit append failed: ${message}`);
      }
    }
  }

  private async handleRequest(request: Request, path: string): Promise<Response> {

    const metadataMatch = path.match(/^\/metadata\/([^/]+)\.json$/);
    if (metadataMatch && request.method === 'GET') {
      const mint = metadataMatch[1]?.trim() ?? '';
      if (!MINT_BASE58_RE.test(mint)) {
        return Response.json({ error: 'invalid mint' }, { status: 400 });
      }

      const events = await this.store.getEvents();
      const linked = events.find((event) => event.solanaMint === mint);

      const title = linked?.title?.trim() || `We-ne Ticket ${mint.slice(0, 6)}`;
      const symbol = buildTokenSymbol(linked?.title?.trim() || '');
      const description = linked
        ? `${linked.title} の参加券トークン`
        : 'we-ne participation ticket token';

      const metadata = {
        name: title,
        symbol,
        description,
        image: TOKEN_IMAGE_URL,
        external_url: 'https://wene-usdc-receipts.pages.dev/',
        attributes: [
          { trait_type: 'mint', value: mint },
          { trait_type: 'event_id', value: linked?.id ?? 'unknown' },
          { trait_type: 'host', value: linked?.host ?? 'unknown' },
          { trait_type: 'datetime', value: linked?.datetime ?? 'unknown' },
          { trait_type: 'claim_interval_days', value: linked?.claimIntervalDays ?? 30 },
          {
            trait_type: 'max_claims_per_interval',
            value: linked?.maxClaimsPerInterval === null
              ? 'unlimited'
              : (linked?.maxClaimsPerInterval ?? 1),
          },
        ],
        properties: {
          category: 'image',
          files: [{ uri: TOKEN_IMAGE_URL, type: 'image/png' }],
        },
      };

      return new Response(JSON.stringify(metadata), {
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'public, max-age=300',
        },
      });
    }

    // GET /api/master/audit-logs (Master Password required)
    if (path === '/api/master/audit-logs' && request.method === 'GET') {
      const authError = this.requireMasterAuthorization(request);
      if (authError) {
        return authError;
      }
      const logs = await this.getAuditLogs();
      return Response.json({ logs });
    }

    // GET /api/master/audit-integrity (Master Password required)
    if (path === '/api/master/audit-integrity' && request.method === 'GET') {
      const authError = this.requireMasterAuthorization(request);
      if (authError) {
        return authError;
      }
      const url = new URL(request.url);
      const limit = parseBoundedInt(
        url.searchParams.get('limit'),
        AUDIT_INTEGRITY_DEFAULT_LIMIT,
        1,
        AUDIT_INTEGRITY_MAX_LIMIT
      );
      const verifyImmutable = parseBooleanQuery(url.searchParams.get('verifyImmutable'), true);
      const report = await this.verifyAuditIntegrity(limit, verifyImmutable);
      const status = report.ok ? 200 : 409;
      return Response.json(report, { status });
    }

    // POST /api/audit/receipts/verify (public)
    if (path === '/api/audit/receipts/verify' && request.method === 'POST') {
      let body: { receipt?: unknown } | undefined;
      try {
        body = (await request.json()) as { receipt?: unknown };
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      const receiptRaw =
        body && typeof body === 'object' && 'receipt' in body
          ? body.receipt
          : body;
      const receipt = this.parseParticipationTicketReceipt(receiptRaw);
      if (!receipt) {
        return Response.json({ error: 'invalid receipt payload' }, { status: 400 });
      }

      const report = await this.verifyParticipationTicketReceipt(receipt);
      const status = report.ok ? 200 : 409;
      return Response.json(report, { status });
    }

    // POST /api/audit/receipts/verify-code (public)
    if (path === '/api/audit/receipts/verify-code' && request.method === 'POST') {
      let body: { eventId?: unknown; confirmationCode?: unknown };
      try {
        body = (await request.json()) as { eventId?: unknown; confirmationCode?: unknown };
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      const eventId = this.normalizeStringField(body?.eventId);
      const confirmationCode = this.normalizeStringField(body?.confirmationCode);
      if (!eventId || !confirmationCode) {
        return Response.json({ error: 'eventId and confirmationCode are required' }, { status: 400 });
      }
      const receipt = this.parseParticipationTicketReceipt(
        await this.ctx.storage.get(ticketReceiptByCodeKey(eventId, confirmationCode))
      );
      if (!receipt) {
        return Response.json({ error: 'ticket receipt not found' }, { status: 404 });
      }
      const verification = await this.verifyParticipationTicketReceipt(receipt);
      const status = verification.ok ? 200 : 409;
      return Response.json({
        ok: verification.ok,
        checkedAt: verification.checkedAt,
        eventId,
        confirmationCode,
        receipt,
        verification,
        verifyByCodeEndpoint: PARTICIPATION_TICKET_VERIFY_BY_CODE_ENDPOINT,
      }, { status });
    }

    // GET /api/admin/transfers (Admin or Master, transfer identifiers visible / PII hidden)
    if (path === '/api/admin/transfers' && request.method === 'GET') {
      const operator = await this.authenticateOperator(request);
      if (!operator) {
        return this.unauthorizedResponse();
      }
      const url = new URL(request.url);
      const limit = parseBoundedInt(
        url.searchParams.get('limit'),
        AUDIT_INTEGRITY_DEFAULT_LIMIT,
        1,
        AUDIT_INTEGRITY_MAX_LIMIT
      );
      const eventIdRaw = url.searchParams.get('eventId');
      const eventId = eventIdRaw && eventIdRaw.trim() ? eventIdRaw.trim() : null;
      const items = await this.getTransferLogs('admin', { limit, eventId });
      return Response.json({
        roleView: 'admin',
        strictLevel: 'admin_transfer_visible_no_pii',
        checkedAt: new Date().toISOString(),
        limit,
        eventId,
        items,
      });
    }

    // GET /api/master/transfers (Master only, full identifiers)
    if (path === '/api/master/transfers' && request.method === 'GET') {
      const authError = this.requireMasterAuthorization(request);
      if (authError) {
        return authError;
      }
      const url = new URL(request.url);
      const limit = parseBoundedInt(
        url.searchParams.get('limit'),
        AUDIT_INTEGRITY_DEFAULT_LIMIT,
        1,
        AUDIT_INTEGRITY_MAX_LIMIT
      );
      const eventIdRaw = url.searchParams.get('eventId');
      const eventId = eventIdRaw && eventIdRaw.trim() ? eventIdRaw.trim() : null;
      const items = await this.getTransferLogs('master', { limit, eventId });
      return Response.json({
        roleView: 'master',
        strictLevel: 'master_full',
        checkedAt: new Date().toISOString(),
        limit,
        eventId,
        items,
      });
    }

    // GET /api/master/admin-disclosures (Master only, full admin-user disclosure)
    if (path === '/api/master/admin-disclosures' && request.method === 'GET') {
      const authError = this.requireMasterAuthorization(request);
      if (authError) {
        return authError;
      }
      const url = new URL(request.url);
      const includeRevoked = parseBooleanQuery(url.searchParams.get('includeRevoked'), true);
      const transferLimit = parseBoundedInt(url.searchParams.get('transferLimit'), 500, 1, 1000);
      const report = await this.getMasterAdminDisclosures({ includeRevoked, transferLimit });
      return Response.json(report);
    }

    // GET /api/master/search (Master only, server-side indexed search)
    if (path === '/api/master/search' && request.method === 'GET') {
      const authError = this.requireMasterAuthorization(request);
      if (authError) {
        return authError;
      }
      const url = new URL(request.url);
      const query = (url.searchParams.get('q') ?? '').trim();
      const includeRevoked = parseBooleanQuery(url.searchParams.get('includeRevoked'), true);
      const transferLimit = parseBoundedInt(url.searchParams.get('transferLimit'), 500, 1, 1000);
      const limit = parseBoundedInt(url.searchParams.get('limit'), 100, 1, 300);
      if (!query) {
        const empty: MasterSearchResponse = {
          checkedAt: new Date().toISOString(),
          strictLevel: 'master_full',
          query,
          includeRevoked,
          transferLimit,
          limit,
          total: 0,
          indexBuiltAt: null,
          items: [],
        };
        return Response.json(empty);
      }

      let total = 0;
      let items: MasterSearchResultItem[] = [];
      let indexBuiltAt: string | null = null;
      const sql = this.getSqlStorageOrNull();

      if (sql) {
        try {
          const sqlMeta = await this.ensureMasterSearchSqlIndex({ includeRevoked, transferLimit });
          if (sqlMeta) {
            const sqlSearch = this.searchMasterIndexSql(sql, sqlMeta.key, query, limit);
            total = sqlSearch.total;
            items = sqlSearch.items;
            indexBuiltAt = sqlMeta.builtAt;
          }
        } catch (err) {
          console.error('[master-search] sqlite index path failed', err);
        }
      }

      if (!indexBuiltAt) {
        const index = await this.getMasterSearchIndex({ includeRevoked, transferLimit });
        const memorySearch = this.searchMasterIndex(index, query, limit);
        total = memorySearch.total;
        items = memorySearch.items;
        indexBuiltAt = index.builtAt;
      }

      const response: MasterSearchResponse = {
        checkedAt: new Date().toISOString(),
        strictLevel: 'master_full',
        query,
        includeRevoked,
        transferLimit,
        limit,
        total,
        indexBuiltAt,
        items,
      };
      return Response.json(response);
    }

    // POST /api/admin/invite (Master Password required)
    if (path === '/api/admin/invite' && request.method === 'POST') {
      const authError = this.requireMasterAuthorization(request);
      if (authError) {
        return authError;
      }

      let body: { name?: string };
      try {
        body = (await request.json()) as any;
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      const name = typeof body?.name === 'string' ? body.name.trim() : 'Unknown Admin';
      if (!name) {
        return Response.json({ error: 'name required' }, { status: 400 });
      }

      const issueLimitError = await this.enforceAdminInviteIssueLimit();
      if (issueLimitError) {
        return issueLimitError;
      }

      // Generate secure random code
      const code = crypto.randomUUID().replace(/-/g, '');
      const adminId = crypto.randomUUID();
      const createdAt = new Date().toISOString();
      await this.ctx.storage.put(adminCodeKey(code), {
        adminId,
        name,
        source: 'invite',
        createdAt,
        revokedAt: null,
        revokedBy: null,
      });

      return Response.json({ code, adminId, name, status: 'active', createdAt });
    }

    // GET /api/admin/invites (Master Password required)
    if (path === '/api/admin/invites' && request.method === 'GET') {
      const authError = this.requireMasterAuthorization(request);
      if (authError) {
        return authError;
      }
      const url = new URL(request.url);
      const includeRevoked = parseBooleanQuery(url.searchParams.get('includeRevoked'), true);
      const result = await this.ctx.storage.list({ prefix: ADMIN_CODE_PREFIX });
      const invites = Array.from(result.entries())
        .map(([key, value]) => {
          const code = key.slice(ADMIN_CODE_PREFIX.length);
          const record = this.parseAdminCodeRecord(code, value);
          if (!record) return null;
          if (!includeRevoked && record.revokedAt) return null;
          return {
            code: record.code,
            adminId: record.adminId,
            name: record.name,
            source: record.source,
            status: record.revokedAt ? 'revoked' : 'active',
            createdAt: record.createdAt,
            revokedAt: record.revokedAt,
            revokedBy: record.revokedBy,
          };
        })
        .filter((item): item is {
          code: string;
          adminId: string;
          name: string;
          source: 'invite';
          status: 'active' | 'revoked';
          createdAt: string;
          revokedAt: string | null;
          revokedBy: string | null;
        } => item !== null);
      invites.sort((a, b) => b.createdAt.localeCompare(a.createdAt));

      return Response.json({ invites });
    }

    // POST /api/admin/rename (Master Password required)
    if (path === '/api/admin/rename' && request.method === 'POST') {
      const authError = this.requireMasterAuthorization(request);
      if (authError) {
        return authError;
      }
      let body: { code?: string; adminId?: string; name?: string };
      try {
        body = (await request.json()) as any;
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      const name = typeof body?.name === 'string' ? body.name.trim() : '';
      if (!name || name.length > 64) {
        return Response.json({ error: 'name must be 1-64 chars' }, { status: 400 });
      }
      const codeFromBody = typeof body?.code === 'string' ? body.code.trim() : '';
      const adminIdFromBody = typeof body?.adminId === 'string' ? body.adminId.trim() : '';
      const code = codeFromBody || (await this.findAdminCodeByAdminId(adminIdFromBody)) || '';
      if (!code) {
        return Response.json({ error: 'code or adminId required' }, { status: 400 });
      }
      const key = adminCodeKey(code);
      const current = this.parseAdminCodeRecord(code, await this.ctx.storage.get(key));
      if (!current) {
        return Response.json({ error: 'admin code not found' }, { status: 404 });
      }
      const updated = {
        ...current,
        name,
      };
      await this.ctx.storage.put(key, updated);
      return Response.json({
        success: true,
        invite: {
          code: updated.code,
          adminId: updated.adminId,
          name: updated.name,
          source: updated.source,
          status: updated.revokedAt ? 'revoked' : 'active',
          createdAt: updated.createdAt,
          revokedAt: updated.revokedAt,
          revokedBy: updated.revokedBy,
        },
      });
    }

    // POST /api/admin/revoke (Master Password required)
    if (path === '/api/admin/revoke' && request.method === 'POST') {
      const authError = this.requireMasterAuthorization(request);
      if (authError) {
        return authError;
      }
      let body: { code?: string };
      try {
        body = (await request.json()) as any;
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      if (typeof body?.code !== 'string') {
        return Response.json({ error: 'code required' }, { status: 400 });
      }
      const code = body.code.trim();
      if (!code) {
        return Response.json({ error: 'code required' }, { status: 400 });
      }
      const key = adminCodeKey(code);
      const current = this.parseAdminCodeRecord(code, await this.ctx.storage.get(key));
      if (!current) {
        return Response.json({ success: false });
      }
      if (current.revokedAt) {
        return Response.json({ success: true, revokedAt: current.revokedAt });
      }
      const revokedAt = new Date().toISOString();
      await this.ctx.storage.put(key, {
        ...current,
        revokedAt,
        revokedBy: 'master',
      });
      return Response.json({ success: true, revokedAt });
    }

    // POST /api/admin/login
    if (path === '/api/admin/login' && request.method === 'POST') {
      let body: { password?: string };
      try {
        body = (await request.json()) as { password?: string };
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }

      const password = typeof body?.password === 'string' ? body.password : '';
      if (this.isDefaultMasterPasswordConfigured() && password === DEFAULT_ADMIN_PASSWORD) {
        return this.insecureMasterPasswordResponse();
      }
      const masterPassword = this.getConfiguredMasterPassword();
      const demoPassword = this.getConfiguredDemoPassword();

      if (masterPassword && password === masterPassword) {
        return Response.json({
          ok: true,
          role: 'master',
          info: {
            adminId: 'master',
            name: 'Master Operator',
            source: 'master',
            status: 'active',
          },
        });
      }

      if (demoPassword && password === demoPassword) {
        return Response.json({
          ok: true,
          role: 'admin',
          info: { adminId: 'demo-admin', name: 'Demo Admin', source: 'demo', status: 'active' },
        });
      }

      // Check Issued Admin Codes
      const adminData = this.parseAdminCodeRecord(password, await this.ctx.storage.get(adminCodeKey(password)));
      if (adminData) {
        if (adminData.revokedAt) {
          return Response.json({ error: 'invite revoked' }, { status: 401 });
        }
        return Response.json({
          ok: true,
          role: 'admin',
          info: {
            adminId: adminData.adminId,
            name: adminData.name,
            source: 'invite',
            createdAt: adminData.createdAt,
            status: 'active',
          },
        });
      }

      return Response.json({ error: 'invalid password' }, { status: 401 });
    }

    if (path === '/v1/school/events' && request.method === 'GET') {
      const url = new URL(request.url);
      const scope = (url.searchParams.get('scope') ?? '').trim().toLowerCase();
      const items = await this.store.getEvents();

      if (scope === 'mine') {
        const operator = await this.authenticateOperator(request);
        if (!operator) {
          return this.unauthorizedResponse();
        }
        if (operator.role === 'master') {
          return Response.json({ items, nextCursor: undefined });
        }

        const ownership = await Promise.all(
          items.map(async (event) => {
            const owner = await this.getEventOwnerRecord(event.id);
            return owner?.adminId === operator.adminId;
          })
        );
        const filtered = items.filter((_, index) => ownership[index] === true);
        return Response.json({ items: filtered, nextCursor: undefined });
      }

      return Response.json({ items, nextCursor: undefined });
    }

    // POST /v1/school/events — イベント新規作成（admin用）
    if (path === '/v1/school/events' && request.method === 'POST') {
      const authError = await this.requireAdminAuthorization(request);
      if (authError) {
        return authError;
      }
      const operator = await this.authenticateOperator(request);
      if (!operator) {
        return this.unauthorizedResponse();
      }

      let body: {
        title?: string;
        datetime?: string;
        host?: string;
        state?: 'draft' | 'published';
        solanaMint?: string;
        solanaAuthority?: string;
        solanaGrantId?: string;
        ticketTokenAmount?: number | string;
        claimIntervalDays?: number | string;
        maxClaimsPerInterval?: number | string | null;
      };
      try {
        body = (await request.json()) as any;
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      const title = typeof body?.title === 'string' ? body.title.trim() : '';
      const datetime = typeof body?.datetime === 'string' ? body.datetime.trim() : '';
      const host = typeof body?.host === 'string' ? body.host.trim() : '';
      const rawTokenAmount = body?.ticketTokenAmount;
      const ticketTokenAmount =
        typeof rawTokenAmount === 'number' && Number.isFinite(rawTokenAmount)
          ? Math.floor(rawTokenAmount)
          : typeof rawTokenAmount === 'string' && /^\d+$/.test(rawTokenAmount.trim())
            ? Number.parseInt(rawTokenAmount.trim(), 10)
            : NaN;
      const rawClaimIntervalDays = body?.claimIntervalDays;
      const claimIntervalDays =
        typeof rawClaimIntervalDays === 'number' && Number.isFinite(rawClaimIntervalDays)
          ? Math.floor(rawClaimIntervalDays)
          : typeof rawClaimIntervalDays === 'string' && /^\d+$/.test(rawClaimIntervalDays.trim())
            ? Number.parseInt(rawClaimIntervalDays.trim(), 10)
            : 30;
      const rawMaxClaimsPerInterval = body?.maxClaimsPerInterval;
      const maxClaimsPerInterval =
        rawMaxClaimsPerInterval === null || rawMaxClaimsPerInterval === 'unlimited'
          ? null
          : typeof rawMaxClaimsPerInterval === 'number' && Number.isFinite(rawMaxClaimsPerInterval)
            ? Math.floor(rawMaxClaimsPerInterval)
            : typeof rawMaxClaimsPerInterval === 'string' && /^\d+$/.test(rawMaxClaimsPerInterval.trim())
              ? Number.parseInt(rawMaxClaimsPerInterval.trim(), 10)
              : 1;

      if (!title || !datetime || !host) {
        return Response.json({ error: 'title, datetime, host are required' }, { status: 400 });
      }
      if (!Number.isInteger(ticketTokenAmount) || ticketTokenAmount <= 0) {
        return Response.json({ error: 'ticketTokenAmount must be a positive integer' }, { status: 400 });
      }
      if (!Number.isInteger(claimIntervalDays) || claimIntervalDays <= 0) {
        return Response.json({ error: 'claimIntervalDays must be a positive integer' }, { status: 400 });
      }
      if (maxClaimsPerInterval !== null && (!Number.isInteger(maxClaimsPerInterval) || maxClaimsPerInterval <= 0)) {
        return Response.json({ error: 'maxClaimsPerInterval must be null or a positive integer' }, { status: 400 });
      }
      const solanaMint = this.normalizeStringField(body.solanaMint);
      const solanaAuthority = this.normalizeStringField(body.solanaAuthority);
      const solanaGrantId = this.normalizeStringField(body.solanaGrantId);
      if (solanaMint && solanaAuthority && solanaGrantId) {
        const events = await this.store.getEvents();
        const duplicated = events.find((event) =>
          this.normalizeStringField(event.solanaMint) === solanaMint &&
          this.normalizeStringField(event.solanaAuthority) === solanaAuthority &&
          this.normalizeStringField(event.solanaGrantId) === solanaGrantId
        );
        if (duplicated) {
          return Response.json(
            { error: `on-chain grant config already linked to event: ${duplicated.id}` },
            { status: 409 }
          );
        }
      }
      const issueLimitError = await this.enforceAdminEventIssueLimit(operator);
      if (issueLimitError) {
        return issueLimitError;
      }
      const event = await this.store.createEvent({
        title, datetime, host, state: body.state,
        solanaMint: solanaMint ?? undefined,
        solanaAuthority: solanaAuthority ?? undefined,
        solanaGrantId: solanaGrantId ?? undefined,
        ticketTokenAmount,
        claimIntervalDays,
        maxClaimsPerInterval,
      });
      await this.ctx.storage.put(eventOwnerKey(event.id), this.operatorToEventOwner(operator));
      // Audit Log
      await this.appendAuditLog(
        'EVENT_CREATE',
        { type: operator.role === 'master' ? 'master' : 'admin', id: operator.actorId },
        {
          title,
          datetime,
          host,
          eventId: event.id,
          createdByAdminId: operator.adminId,
          createdByAdminName: operator.name,
          createdBySource: operator.source,
          solanaMint,
          solanaAuthority,
          solanaGrantId,
          ticketTokenAmount,
          claimIntervalDays,
          maxClaimsPerInterval,
        },
        event.id
      );
      return Response.json(event, { status: 201 });
    }

    const eventIdMatch = path.match(/^\/v1\/school\/events\/([^/]+)$/);
    if (eventIdMatch && request.method === 'GET') {
      const eventId = eventIdMatch[1];
      const event = await this.store.getEvent(eventId);
      if (!event) {
        return Response.json(
          { success: false, error: { code: 'not_found', message: 'イベントが見つかりません' } } as SchoolClaimResult,
          { status: 404 }
        );
      }
      return Response.json(event);
    }

    // POST /v1/school/events/:eventId/close — イベントを終了状態へ
    const closeEventMatch = path.match(/^\/v1\/school\/events\/([^/]+)\/close$/);
    if (closeEventMatch && request.method === 'POST') {
      const authError = await this.requireAdminAuthorization(request);
      if (authError) {
        return authError;
      }
      const operator = await this.authenticateOperator(request);
      if (!operator) {
        return this.unauthorizedResponse();
      }
      const eventId = closeEventMatch[1];
      const event = await this.store.getEvent(eventId);
      if (!event) {
        return Response.json({ error: 'event not found' }, { status: 404 });
      }
      const forbidden = await this.ensureOperatorCanAccessEvent(operator, eventId);
      if (forbidden) {
        return forbidden;
      }
      const previousState = event.state ?? 'published';
      if (previousState === 'ended') {
        return Response.json(event);
      }
      const updated = await this.store.updateEventState(eventId, 'ended');
      if (!updated) {
        return Response.json({ error: 'event not found' }, { status: 404 });
      }
      await this.appendAuditLog(
        'EVENT_CLOSE',
        { type: operator.role === 'master' ? 'master' : 'admin', id: operator.actorId },
        {
          eventId,
          previousState,
          nextState: 'ended',
          closedByAdminId: operator.adminId,
          closedByAdminName: operator.name,
          closedBySource: operator.source,
        },
        eventId
      );
      return Response.json(updated);
    }

    // GET /v1/school/events/:eventId/claimants — 参加者一覧
    const claimantsMatch = path.match(/^\/v1\/school\/events\/([^/]+)\/claimants$/);
    if (claimantsMatch && request.method === 'GET') {
      const authError = await this.requireAdminAuthorization(request);
      if (authError) {
        return authError;
      }

      const eventId = claimantsMatch[1];
      const event = await this.store.getEvent(eventId);
      if (!event) {
        return Response.json({ error: 'event not found' }, { status: 404 });
      }
      const operator = await this.authenticateOperator(request);
      if (!operator) {
        return this.unauthorizedResponse();
      }
      const forbidden = await this.ensureOperatorCanAccessEvent(operator, eventId);
      if (forbidden) {
        return forbidden;
      }
      const claimants = await this.store.getClaimants(eventId);
      // subject が user ID の場合 displayName を引く
      const items = await Promise.all(claimants.map(async (c) => {
        let displayName: string | undefined;
        const userRaw = await this.ctx.storage.get(userKey(c.subject));
        if (userRaw && typeof userRaw === 'object' && 'displayName' in userRaw) {
          displayName = (userRaw as { displayName: string }).displayName;
        }
        return {
          subject: c.subject,
          displayName: displayName ?? '-',
          confirmationCode: c.confirmationCode,
          claimedAt: c.claimedAt ? new Date(c.claimedAt).toISOString() : undefined,
        };
      }));
      return Response.json({ eventId, eventTitle: event.title, items });
    }

    if (path === '/v1/school/pop-status' && request.method === 'GET') {
      let signerConfigured = false;
      let signerPubkey: string | null = null;
      let error: string | null = null;
      try {
        const signer = this.getPopSigner();
        signerConfigured = signer !== null;
        signerPubkey = signer?.signerPubkey ?? null;
      } catch (err) {
        error = err instanceof Error ? err.message : String(err);
      }
      return Response.json({
        enforceOnchainPop: this.isOnchainPopEnforced(),
        signerConfigured,
        signerPubkey,
        error,
      });
    }

    if (path === '/v1/school/audit-status' && request.method === 'GET') {
      return Response.json(this.getAuditStatus());
    }

    if (path === '/v1/school/runtime-status' && request.method === 'GET') {
      return Response.json(this.getRuntimeStatus());
    }

    if (path === '/v1/school/pop-proof' && request.method === 'POST') {
      let body: PopProofBody;
      try {
        body = (await request.json()) as PopProofBody;
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      try {
        const proof = await this.issuePopClaimProof(body);
        return Response.json(proof);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const status =
          message.includes('not configured') ? 500 :
            message.includes('not found') ? 404 :
              message.includes('verification failed') ? 409 :
                message.includes('not available') ? 400 :
                  message.includes('invalid') || message.includes('out of range') ? 400 : 500;
        return Response.json({ error: message }, { status });
      }
    }

    if (path === '/v1/school/claims' && request.method === 'POST') {
      let body: ClaimBody;
      try {
        body = (await request.json()) as ClaimBody;
      } catch {
        return Response.json({
          success: false,
          error: { code: 'invalid', message: 'イベントIDが無効です' },
        } as SchoolClaimResult);
      }
      const fairscaleToken = this.extractFairscaleToken(request, body);
      const eventId = typeof body?.eventId === 'string' ? body.eventId.trim() : '';
      const event = eventId ? await this.store.getEvent(eventId) : null;
      if (!event) {
        return Response.json({
          success: false,
          error: { code: 'not_found', message: 'イベントが見つかりません' },
        } as SchoolClaimResult);
      }
      if (this.isOnchainPopEnforced() && this.isEventOnchainConfigured(event)) {
        const fields = this.getOnchainProofFields(body);
        const hasOnchainProof = this.hasAnyOnchainProofField(fields);
        if (hasOnchainProof) {
          let signerConfigured = false;
          try {
            signerConfigured = this.getPopSigner() !== null;
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            return Response.json({
              success: false,
              error: { code: 'retryable', message: `PoP設定エラー: ${message}` },
            } as SchoolClaimResult);
          }
          if (!signerConfigured) {
            return Response.json({
              success: false,
              error: { code: 'retryable', message: 'PoP署名設定が未完了のためオンチェーン参加を受け付けできません' },
            } as SchoolClaimResult);
          }
          const invalidReason = this.validateOnchainProofFields(fields);
          if (invalidReason) {
            return Response.json({
              success: false,
              error: { code: 'wallet_required', message: `オンチェーンPoP証跡が必要です: ${invalidReason}` },
            } as SchoolClaimResult);
          }
        }
      }
      const walletAddress = this.normalizeStringField(body.walletAddress);
      const joinToken = this.normalizeStringField(body.joinToken);
      const subject = normalizeSubject(walletAddress ?? undefined, joinToken ?? undefined);
      if (!subject) {
        return Response.json({
          success: false,
          error: { code: 'wallet_required', message: 'Phantomに接続してください' },
        } as SchoolClaimResult);
      }
      const alreadyClaimed = await this.store.hasClaimed(eventId, subject, event);
      if (!alreadyClaimed) {
        const fairscaleError = await this.enforceFairscaleRisk({
          request,
          action: 'wallet_claim',
          eventId,
          subject,
          fairscaleToken: fairscaleToken || undefined,
        });
        if (fairscaleError) {
          return Response.json(this.mapFairscaleErrorToSchoolClaimResult(fairscaleError), {
            status: fairscaleError.status,
          });
        }
      }

      let issuedConfirmationCode: string;
      try {
        issuedConfirmationCode = await this.reserveUniqueConfirmationCode(eventId, subject);
      } catch {
        return Response.json({
          success: false,
          error: { code: 'retryable', message: '確認コードの発行に失敗しました。時間を置いて再試行してください。' },
        } as SchoolClaimResult);
      }

      let result: SchoolClaimResult;
      try {
        result = await this.store.submitClaim(body, { confirmationCode: issuedConfirmationCode });
      } catch (err) {
        await this.releaseReservedConfirmationCode(eventId, subject, issuedConfirmationCode);
        throw err;
      }
      if (!result.success) {
        await this.releaseReservedConfirmationCode(eventId, subject, issuedConfirmationCode);
        return Response.json(result);
      }

      let confirmationCode = result.confirmationCode;
      if (!confirmationCode) {
        const rec = await this.store.getClaimRecord(eventId, subject);
        confirmationCode = rec?.confirmationCode;
      }
      if (confirmationCode) {
        await this.ensureConfirmationCodeIndexed(eventId, subject, confirmationCode);
        if (confirmationCode !== issuedConfirmationCode) {
          await this.releaseReservedConfirmationCode(eventId, subject, issuedConfirmationCode);
        }
      }

      if (result.alreadyJoined) {
        await this.releaseReservedConfirmationCode(eventId, subject, issuedConfirmationCode);
        const ticketReceipt =
          confirmationCode
            ? await this.getParticipationTicketReceipt(eventId, subject, confirmationCode)
            : null;
        const alreadyResponse: SchoolClaimResultSuccess = {
          ...result,
          ...(confirmationCode ? { confirmationCode } : {}),
          ...(ticketReceipt ? { ticketReceipt } : {}),
        };
        return Response.json(alreadyResponse);
      }

      const txSignature = this.normalizeStringField(body.txSignature);
      const receiptPubkey = this.normalizeStringField(body.receiptPubkey);
      const recipient: TransferParty | null = walletAddress
        ? { type: 'wallet', id: walletAddress }
        : joinToken
          ? { type: 'join_token', id: joinToken }
          : null;
      const pii: Record<string, string> = {};
      if (walletAddress) pii.walletAddress = walletAddress;
      if (joinToken) pii.joinToken = joinToken;

      let auditEntry: AuditEvent;
      if (recipient) {
        auditEntry = await this.appendAuditLog(
          'WALLET_CLAIM',
          { type: 'wallet', id: recipient.id },
          {
            eventId,
            status: 'created',
            ...(confirmationCode ? { confirmationCode } : {}),
            transfer: this.buildClaimTransferPayload({
              eventId,
              event,
              recipient,
              txSignature,
              receiptPubkey,
            }),
            ...(Object.keys(pii).length > 0 ? { pii } : {}),
          },
          eventId
        );
      } else {
        auditEntry = await this.appendAuditLog(
          'WALLET_CLAIM',
          { type: 'wallet', id: 'unknown' },
          {
            eventId,
            status: 'created',
            ...(confirmationCode ? { confirmationCode } : {}),
          },
          eventId
        );
      }

      const ticketReceipt =
        confirmationCode
          ? await this.buildParticipationTicketReceipt({
            eventId,
            subject,
            confirmationCode,
            auditEntry,
          })
          : null;
      if (ticketReceipt) {
        await this.storeParticipationTicketReceipt(eventId, subject, ticketReceipt);
      }

      const createdResponse: SchoolClaimResultSuccess = {
        ...result,
        ...(confirmationCode ? { confirmationCode } : {}),
        ...(ticketReceipt ? { ticketReceipt } : {}),
      };
      return Response.json(createdResponse);
    }

    // POST /api/auth/verify
    if (path === '/api/auth/verify' && request.method === 'POST') {
      let body: { userId?: string; pin?: string };
      try {
        body = (await request.json()) as { userId?: string; pin?: string };
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      const userId = this.normalizeUserId(body?.userId);
      const pin = typeof body?.pin === 'string' ? body.pin : '';
      if (!userId || !pin) {
        return Response.json({ error: 'missing params' }, { status: 400 });
      }
      const userRaw = await this.ctx.storage.get(userKey(userId));
      if (!userRaw || typeof userRaw !== 'object' || !('pinHash' in userRaw)) {
        return Response.json({ message: 'User not found', code: 'user_not_found' }, { status: 401 });
      }
      const pinHash = await hashPin(pin);
      if ((userRaw as { pinHash: string }).pinHash !== pinHash) {
        return Response.json({ message: 'Invalid PIN', code: 'invalid_pin' }, { status: 401 });
      }
      return Response.json({ ok: true });
    }

    // POST /api/users/tickets/sync
    if (path === '/api/users/tickets/sync' && request.method === 'POST') {
      let body: UserTicketSyncBody;
      try {
        body = (await request.json()) as UserTicketSyncBody;
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      const userId = this.normalizeUserId(body?.userId);
      const pin = typeof body?.pin === 'string' ? body.pin : '';
      if (!userId || !pin) {
        return Response.json({ error: 'missing params' }, { status: 400 });
      }

      const userRaw = await this.ctx.storage.get(userKey(userId));
      if (!userRaw || typeof userRaw !== 'object' || !('pinHash' in userRaw)) {
        return Response.json({ message: 'User not found', code: 'user_not_found' }, { status: 401 });
      }
      const pinHash = await hashPin(pin);
      if ((userRaw as { pinHash: string }).pinHash !== pinHash) {
        return Response.json({ message: 'Invalid PIN', code: 'invalid_pin' }, { status: 401 });
      }

      const tickets = await this.buildUserTicketSyncItems(userId);
      return Response.json({
        syncedAt: new Date().toISOString(),
        tickets,
      } satisfies UserTicketSyncResponse);
    }

    // POST /api/users/register
    if (path === '/api/users/register' && request.method === 'POST') {
      let body: RegisterBody;
      try {
        body = (await request.json()) as RegisterBody;
      } catch {
        return Response.json({ error: 'invalid body' }, { status: 400 });
      }
      const userId = this.normalizeUserId(body?.userId);
      const displayName = typeof body?.displayName === 'string' ? body.displayName.trim().slice(0, 32) : '';
      const pin = typeof body?.pin === 'string' ? body.pin : '';
      const userIdError = this.validateUserIdForRegistration(userId);
      if (userIdError) {
        return Response.json({ error: userIdError, code: 'invalid_user_id' }, { status: 400 });
      }
      if (!displayName || displayName.length < 1) {
        return Response.json({ error: 'displayName required (nickname 1-32)' }, { status: 400 });
      }
      if (!/^\d{4,6}$/.test(pin)) {
        return Response.json({ error: 'pin must be 4-6 digits' }, { status: 400 });
      }
      const fairscaleToken = this.extractFairscaleToken(request, body);
      const fairscaleError = await this.enforceFairscaleRisk({
        request,
        action: 'user_register',
        userId,
        subject: userId,
        fairscaleToken: fairscaleToken || undefined,
      });
      if (fairscaleError) {
        return this.fairscaleErrorResponse(fairscaleError);
      }
      const pinHash = await hashPin(pin);
      const registerResult = await this.registerUserWithUniqueId({
        userId,
        displayName,
        pinHash,
      });
      if (!registerResult.ok) {
        return Response.json({ error: 'userId already exists', code: 'duplicate_user_id' }, { status: 409 });
      }

      // Audit Log
      await this.appendAuditLog(
        'USER_REGISTER',
        { type: 'user', id: userId },
        {
          displayName,
          userIdHash: registerResult.userIdHash,
          userIdChainHash: registerResult.chainHash,
          userIdPrevChainHash: registerResult.prevChainHash,
        },
        'system'
      );

      return Response.json({ userId });
    }

    // POST /api/events/:eventId/claim (userId + pin)
    const claimMatch = path.match(/^\/api\/events\/([^/]+)\/claim$/);
    if (claimMatch && request.method === 'POST') {
      const eventId = claimMatch[1].trim();
      let body: UserClaimBody;
      try {
        body = (await request.json()) as UserClaimBody;
      } catch {
        return Response.json({ error: 'missing params' }, { status: 400 });
      }
      const fairscaleToken = this.extractFairscaleToken(request, body);
      const userId = this.normalizeUserId(body?.userId);
      const pin = typeof body?.pin === 'string' ? body.pin : '';
      if (!userId || !pin) {
        return Response.json({ error: 'missing params' }, { status: 400 });
      }
      const userRaw = await this.ctx.storage.get(userKey(userId));
      if (!userRaw || typeof userRaw !== 'object' || !('pinHash' in userRaw)) {
        return Response.json({ message: 'User not found', code: 'user_not_found' }, { status: 401 });
      }
      const pinHash = await hashPin(pin);
      if ((userRaw as { pinHash: string }).pinHash !== pinHash) {
        return Response.json({ message: 'Invalid PIN', code: 'invalid_pin' }, { status: 401 });
      }
      const event = await this.store.getEvent(eventId);
      if (!event) {
        return Response.json({ error: 'event not found' }, { status: 404 });
      }
      if (event.state && event.state !== 'published') {
        return Response.json({ error: 'event not available' }, { status: 400 });
      }
      const proofFields = this.getOnchainProofFields(body);
      const hasOnchainProof = this.hasAnyOnchainProofField(proofFields);
      if (this.isOnchainPopEnforced() && this.isEventOnchainConfigured(event) && hasOnchainProof) {
        let signerConfigured = false;
        try {
          signerConfigured = this.getPopSigner() !== null;
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          return Response.json({ error: `PoP configuration error: ${message}` }, { status: 500 });
        }
        if (!signerConfigured) {
          return Response.json({ error: 'PoP signer is not configured' }, { status: 500 });
        }
        const invalidReason = this.validateOnchainProofFields(proofFields);
        if (invalidReason) {
          return Response.json({ error: `on-chain claim proof required: ${invalidReason}` }, { status: 400 });
        }
      }
      const already = await this.store.hasClaimed(eventId, userId, event);
      if (!already && hasOnchainProof) {
        return Response.json({
          error: 'on-chain claim requires off-chain receipt verification first',
          code: 'offchain_receipt_required',
        }, { status: 409 });
      }
      if (!already) {
        const fairscaleError = await this.enforceFairscaleRisk({
          request,
          action: 'user_claim',
          eventId,
          userId,
          subject: userId,
          fairscaleToken: fairscaleToken || undefined,
        });
        if (fairscaleError) {
          return this.fairscaleErrorResponse(fairscaleError);
        }
      }
      if (already) {
        const rec = await this.store.getClaimRecord(eventId, userId);
        let confirmationCode = rec?.confirmationCode;
        if (!confirmationCode) {
          try {
            confirmationCode = await this.reserveUniqueConfirmationCode(eventId, userId);
            await this.store.setLatestClaimConfirmationCode(eventId, userId, confirmationCode);
          } catch {
            return Response.json({ error: 'failed to issue confirmation code' }, { status: 500 });
          }
        }
        await this.ensureConfirmationCodeIndexed(eventId, userId, confirmationCode);
        const ticketReceipt = await this.getParticipationTicketReceipt(eventId, userId, confirmationCode);
        if (hasOnchainProof) {
          if (!ticketReceipt) {
            return Response.json({
              error: 'off-chain receipt not found for this participation',
              code: 'offchain_receipt_not_found',
            }, { status: 409 });
          }
          const verification = await this.verifyParticipationTicketReceipt(ticketReceipt);
          if (!verification.ok) {
            return Response.json({
              error: 'off-chain receipt verification failed',
              code: 'offchain_receipt_invalid',
              verification,
            }, { status: 409 });
          }
        }
        if (hasOnchainProof) {
          const displayName = this.normalizeStringField((userRaw as { displayName?: unknown }).displayName);
          const recipient: TransferParty = proofFields.walletAddress
            ? { type: 'wallet', id: proofFields.walletAddress }
            : { type: 'user', id: userId };
          const pii: Record<string, string> = { userId };
          if (proofFields.walletAddress) pii.walletAddress = proofFields.walletAddress;
          if (displayName) pii.displayName = displayName;
          await this.appendAuditLog(
            'USER_CLAIM',
            { type: 'user', id: userId },
            {
              eventId,
              status: 'already',
              confirmationCode,
              transfer: this.buildClaimTransferPayload({
                eventId,
                event,
                recipient,
                txSignature: proofFields.txSignature,
                receiptPubkey: proofFields.receiptPubkey,
              }),
              pii,
            },
            eventId
          );
        }
        return Response.json({
          status: 'already',
          confirmationCode,
          ...(ticketReceipt ? { ticketReceipt } : {}),
        } as UserClaimResponse);
      }
      let confirmationCode: string | null = null;
      try {
        confirmationCode = await this.reserveUniqueConfirmationCode(eventId, userId);
        await this.store.addClaim(eventId, userId, confirmationCode);
      } catch {
        if (confirmationCode) {
          await this.releaseReservedConfirmationCode(eventId, userId, confirmationCode);
        }
        return Response.json({ error: 'failed to issue confirmation code' }, { status: 500 });
      }
      if (!confirmationCode) {
        return Response.json({ error: 'failed to issue confirmation code' }, { status: 500 });
      }
      await this.ensureConfirmationCodeIndexed(eventId, userId, confirmationCode);

      // Audit Log
      const displayName = this.normalizeStringField((userRaw as { displayName?: unknown }).displayName);
      const walletAddress = hasOnchainProof
        ? proofFields.walletAddress
        : this.normalizeStringField(body.walletAddress);
      const recipient: TransferParty = walletAddress
        ? { type: 'wallet', id: walletAddress }
        : { type: 'user', id: userId };
      const pii: Record<string, string> = { userId };
      if (displayName) pii.displayName = displayName;
      if (walletAddress) pii.walletAddress = walletAddress;

      const auditEntry = await this.appendAuditLog(
        'USER_CLAIM',
        { type: 'user', id: userId },
        {
          eventId,
          status: 'created',
          confirmationCode,
          transfer: this.buildClaimTransferPayload({
            eventId,
            event,
            recipient,
            txSignature: hasOnchainProof ? proofFields.txSignature : body.txSignature,
            receiptPubkey: hasOnchainProof ? proofFields.receiptPubkey : body.receiptPubkey,
          }),
          pii,
        },
        eventId
      );
      const ticketReceipt = await this.buildParticipationTicketReceipt({
        eventId,
        subject: userId,
        confirmationCode,
        auditEntry,
      });
      await this.storeParticipationTicketReceipt(eventId, userId, ticketReceipt);

      return Response.json({ status: 'created', confirmationCode, ticketReceipt } as UserClaimResponse);
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': this.env.CORS_ORIGIN || '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Fairscale-Token',
        },
      });
    }

    return new Response('Not Found', { status: 404 });
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    const securityError = await this.enforceSecurityPreflight(request, path);
    if (securityError) {
      return securityError;
    }

    // Fail closed before side-effects when immutable audit is required but not operational.
    // This avoids mutating state and then failing later during audit append.
    if (this.isApiPath(path) && this.isAuditFailClosed(path, request.method)) {
      const auditStatus = this.getAuditStatus();
      if (!auditStatus.operationalReady) {
        return Response.json({
          error: 'audit immutable sink is not operational',
          detail: 'Set AUDIT_LOGS or AUDIT_IMMUTABLE_INGEST_URL before mutating APIs in required mode',
          audit: auditStatus,
        }, { status: 503 });
      }
    }

    const startedAt = Date.now();
    const requestBody = await this.requestBodyForAudit(request);

    let response: Response;
    let errorMessage: string | undefined;

    try {
      response = await this.handleRequest(request, path);
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : String(err);
      response = Response.json({ error: 'internal server error' }, { status: 500 });
    }

    try {
      await this.appendApiAuditTrail(request, url, path, response, requestBody, startedAt, errorMessage);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (this.isAuditFailClosed(path, request.method)) {
        return Response.json({ error: 'audit log persistence failed', detail: message }, { status: 503 });
      }
      console.error('[audit] non-blocking append failure', { path, method: request.method, message });
    }
    return response;
  }
}
