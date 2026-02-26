# 学校PoC API（Cloudflare Workers）

Hono による最小構成の API。`wene-mobile`（Cloudflare Pages）から固定HTTPSで接続し、学校運用を完結させる。

## API 仕様

- `GET /v1/school/events`  
  - レスポンス: `{ items: SchoolEvent[]; nextCursor?: string }`  
  - 各 item に `claimedCount` を含む
- `GET /v1/school/events/:eventId`  
  - レスポンス: `SchoolEvent`（`claimedCount` 含む）。存在しなければ 404 + `SchoolClaimResult`（not_found）
- `POST /v1/school/events`
  - リクエスト: `{ title: string; datetime: string; host: string; state?: 'draft'|'published'; solanaMint?: string; solanaAuthority?: string; solanaGrantId?: string; ticketTokenAmount: number; claimIntervalDays?: number; maxClaimsPerInterval?: number | null }`
  - `ticketTokenAmount` は 1 以上の整数（数値文字列も許容）
  - `claimIntervalDays` は 1 以上の整数（未指定時 30）
  - `maxClaimsPerInterval` は `null`（無制限）または 1 以上の整数（未指定時 1）
  - `solanaAuthority + solanaMint + solanaGrantId` が既存イベントと重複する場合は 409（同一 grant のイベント再利用を禁止）
  - レスポンス: 作成された `SchoolEvent`
- `POST /v1/school/claims`  
  - リクエスト: `{ eventId: string; walletAddress?: string; joinToken?: string; txSignature?: string; receiptPubkey?: string }`  
  - レスポンス: `SchoolClaimResult`（`success=true` の場合 `confirmationCode` と `ticketReceipt` を返却）  
  - **walletAddress 未指定かつ joinToken 未指定** → `wallet_required`（Phantom誘導用）  
  - `ENFORCE_ONCHAIN_POP=true` かつ on-chain 設定済みイベント（`solanaMint`/`solanaAuthority`/`solanaGrantId`）では、`walletAddress + txSignature + receiptPubkey` を必須化
  - `POST /api/events/:eventId/claim`（userId+PIN）でも同様に on-chain 証跡を必須化
  - **evt-003** → 常に `retryable`（デモ用）
- `POST /api/events/:eventId/claim`（userId + PIN）
  - レスポンス: `{ status: 'created'|'already'; confirmationCode: string; ticketReceipt?: ParticipationTicketReceipt }`
  - `ticketReceipt` は監査ログの不変レシート（`entry_hash`, `prev_hash`, immutable sink 情報, `receiptHash`）を含む
- `POST /api/audit/receipts/verify`（公開）
  - リクエスト: `{ receipt: ParticipationTicketReceipt }`（または receipt オブジェクト直送）
  - レスポンス: `ok`, `checks`, `issues`, `proof`
  - 第三者が受け取った参加券レシートの整合性（ハッシュ・監査チェーン・immutable payload）を検証できる
- `POST /api/audit/receipts/verify-code`（公開）
  - リクエスト: `{ eventId: string; confirmationCode: string }`
  - レスポンス: `{ ok, receipt, verification }`
  - 参加券のコードだけで第三者検証を実行できる（審査・監査導線向け）
- `GET /v1/school/pop-status`
  - レスポンス: `{ enforceOnchainPop: boolean; signerConfigured: boolean; signerPubkey?: string | null; error?: string | null }`
- `GET /v1/school/audit-status`
  - レスポンス: `{ mode: 'off'|'best_effort'|'required'; failClosedForMutatingRequests: boolean; operationalReady: boolean; primaryImmutableSinkConfigured: boolean; sinks: { r2Configured: boolean; kvConfigured: boolean; ingestConfigured: boolean } }`
- `GET /v1/school/runtime-status`
  - レスポンス: `{ ready: boolean; checks: {...}; blockingIssues: string[]; warnings: string[] }`
  - 実運用の前提（`ADMIN_PASSWORD`、PoP signer、監査 immutable sink）を一括で確認
- `GET /api/master/audit-integrity`（Master Password 必須）
  - クエリ: `limit`（既定 50, 最大 200）, `verifyImmutable`（既定 true）
  - レスポンス: `ok`, `issues[]`, `warnings[]` を含む整合性レポート（`ok=false` の場合 HTTP 409）
- `GET /api/admin/transfers`（Admin / Master）
  - クエリ: `eventId`（任意）, `limit`（既定 50, 最大 200）
  - レスポンス: `roleView: "admin"`, `strictLevel: "admin_transfer_visible_no_pii"`, `items[]`
  - `items[].transfer` に送金主/送金先ID・mint・amount・txSignature・receiptPubkey を含む
  - `items[].pii` は返却しない（運用者PIIはマスク）
- `GET /api/master/transfers`（Master Password 必須）
  - クエリ: `eventId`（任意）, `limit`（既定 50, 最大 200）
  - レスポンス: `roleView: "master"`, `strictLevel: "master_full"`, `items[]`
  - `items[].pii` を含む完全監査ビュー（`運営 > 管理者` レベル）
- `GET /api/master/admin-disclosures`（Master Password 必須）
  - クエリ: `includeRevoked`（既定 true）, `transferLimit`（既定 500, 最大 1000）
  - レスポンス: `strictLevel: "master_full"`, `admins[]`
  - `admins[]` に adminId/code/name/status + 関連イベント + 関連ユーザー/claim（transfer + pii）を返却
- `GET /api/master/search`（Master Password 必須）
  - クエリ: `q`（必須）, `limit`（既定 100, 最大 300）, `includeRevoked`（既定 true）, `transferLimit`（既定 500, 最大 1000）
  - レスポンス: `strictLevel: "master_full"`, `total`, `items[]`
  - `items[]` は `admin/event/user/claim` の横断検索結果。サーバー側で転置インデックス化して返却
  - Durable Object の SQLite (`ctx.storage.sql`) にインデックスを永続化し、コールドスタート時も再計算コストを抑制
- `POST /api/admin/rename`（Master Password 必須）
  - リクエスト: `{ name: string; code?: string; adminId?: string }`
  - `code` か `adminId` のどちらか必須
  - 既存の管理者レコード名を更新して返却（status/revoked情報は維持）
- `POST /v1/audit/log`（監査ログ強制書き込み用）
  - Authorization 必須（`Bearer <AUDIT_LOG_WRITE_TOKEN>`。未設定時は `ADMIN_PASSWORD`）
  - `AUDIT_LOG_WRITE_TOKEN` / `ADMIN_PASSWORD` が無効な設定の場合は 503

## 不変レシート参加券（wallet不要）を採用する理由

- 学校現場では、全参加者がウォレットを保有している前提を置けないため
- `confirmationCode + ticketReceipt` により、参加証明をウォレット非依存で配布・保管できるため
- `POST /api/audit/receipts/verify` により、第三者検証可能な監査連鎖を維持できるため
- 本プロジェクトではこの学校運用を、ハッシュチェーンの社会検証における第一検証として位置づけているため

### 運用モデル（Attend / Redeem）

- Attend（主導線）: `POST /api/events/:eventId/claim` で `userId + PIN` により参加券（不変レシート）を発行
- Attend（学校導線）: `POST /v1/school/claims` でも同様に `confirmationCode + ticketReceipt` を発行
- Redeem（任意）: イベントが on-chain 設定済みで `ENFORCE_ONCHAIN_POP=true` の場合のみ wallet + tx + receipt を要求

重要な整理:
- 学校ユースケースでの基本価値は Attend で完結する
- Redeem は追加要件が必要な運用時だけ有効化する拡張パス
- PoP チェーン復旧（reset/fork handling/stream cut）は `../docs/POP_CHAIN_OPERATIONS.md` を参照

契約型は `src/types.ts`（wene-mobile の `SchoolEvent` / `SchoolClaimResult` と一致）。

## ローカル起動

```bash
cd api-worker
npm i
npx wrangler dev
```

デフォルトで `http://localhost:8787` で待ち受ける。Pages の `.env` で `EXPO_PUBLIC_API_BASE_URL=http://localhost:8787` にするとローカルで UI と接続できる。

## デプロイ

```bash
cd api-worker
npm i
npx wrangler deploy
```

デプロイ後に表示される URL（正規: `https://wene-usdc-receipts-api.haruki-kira3.workers.dev`）を、Pages の環境変数 `EXPO_PUBLIC_API_BASE_URL` に設定する。

### PoP（Proof of Process）署名設定（必須）

L1 で PoP 検証を行うため、以下の Worker 変数を設定する:

- `POP_SIGNER_SECRET_KEY_B64`: Ed25519 の 32byte seed または 64byte secret key を base64 で設定
- `POP_SIGNER_PUBKEY`: 対応する公開鍵（base58）
- `ENFORCE_ONCHAIN_POP`: on-chain 設定イベントで PoP 証跡を必須化（推奨: `true`、未設定時も強制）
- `AUDIT_IMMUTABLE_MODE`: `required`（推奨） / `best_effort` / `off`
- `AUDIT_IMMUTABLE_FETCH_TIMEOUT_MS`: immutable ingest 送信タイムアウト（ms、既定 5000）
- `AUDIT_IMMUTABLE_INGEST_URL`: 任意。R2 に加えて外部 immutable sink に二重固定化したい場合に設定
- `AUDIT_LOG_WRITE_TOKEN`: 任意。`POST /v1/audit/log` を有効化する場合の専用トークン

### Anti-Bot / DDoS ガードレール

以下の Worker 変数で API レベルの防御を調整できる:

- `SECURITY_RATE_LIMIT_ENABLED`: レート制限の有効/無効（既定 `true`）
- `SECURITY_RATE_LIMIT_READ_PER_MINUTE`: 読み取り系 API の上限（1分）
- `SECURITY_RATE_LIMIT_MUTATION_PER_MINUTE`: 更新系 API の上限（1分）
- `SECURITY_RATE_LIMIT_AUTH_PER_10_MINUTES`: `auth/claim/register/sync` 系の上限（10分）
- `SECURITY_RATE_LIMIT_ADMIN_LOGIN_PER_10_MINUTES`: 管理者ログインの上限（10分）
- `SECURITY_RATE_LIMIT_VERIFY_PER_MINUTE`: レシート検証 API の上限（1分）
- `SECURITY_RATE_LIMIT_GLOBAL_PER_MINUTE`: API 全体のグローバル上限（1分）
- `SECURITY_RATE_LIMIT_BLOCK_SECONDS`: 超過時の初期ブロック秒数（違反回数で指数バックオフ）
- `SECURITY_MAX_REQUEST_BODY_BYTES`: 更新系 API の最大リクエストサイズ（bytes、超過は `413`）
- `SECURITY_ADMIN_EVENT_ISSUE_LIMIT_PER_DAY`: 管理者ごとのイベント発行上限（日次, `0`以下で無効）
- `SECURITY_ADMIN_INVITE_ISSUE_LIMIT_PER_DAY`: Master の管理者コード発行上限（日次, `0`以下で無効）

制限超過時は `429`（`Retry-After` 付き）を返す。

### FairScale Sybil Guard（任意）

FairScale 互換のリスク判定 API を登録/参加導線に組み込める:

- `FAIRSCALE_ENABLED`: FairScale 判定を有効化（既定は `FAIRSCALE_BASE_URL` 設定時のみ有効）
- `FAIRSCALE_FAIL_CLOSED`: 判定API障害時に遮断するか（`true`=503で遮断, `false`=fail-open）
- `FAIRSCALE_BASE_URL`: 判定APIのベースURL
- `FAIRSCALE_VERIFY_PATH`: 判定APIパス（既定 `/v1/risk/score`。URL全体指定も可）
- `FAIRSCALE_API_KEY`: 判定APIの認証キー（Bearer + `x-api-key` で送信）
- `FAIRSCALE_TIMEOUT_MS`: 判定APIタイムアウト（ms）
- `FAIRSCALE_MIN_SCORE`: 許容スコア下限（0-100）
- `FAIRSCALE_ENFORCE_ON_REGISTER`: `/api/users/register` に適用するか
- `FAIRSCALE_ENFORCE_ON_CLAIM`: `/api/events/:eventId/claim` と `/v1/school/claims` に適用するか

ブロック時は `403`（`fairscale_blocked`）、fail-closed で判定不能時は `503` を返す。

`POST /v1/school/pop-proof` はこの鍵で署名した PoP 証明を返し、クライアントは `claim_grant` 送信前に Ed25519 検証命令を付与する。
デプロイ後は次を確認してから本番運用に入ること:
- `GET /v1/school/pop-status` で `signerConfigured: true`
- `GET /v1/school/audit-status` で `operationalReady: true`
- `GET /api/master/audit-integrity?limit=50` が `ok: true`
- `GET /api/admin/transfers?limit=20`（AdminまたはMaster）で `roleView: "admin"` が返る
- `GET /api/master/transfers?limit=20`（Master）で `roleView: "master"` が返る

## CORS

この Worker は次の優先順で CORS を判定する。

1. リクエスト `Origin` が `*.pages.dev` または `localhost` の場合は、その `Origin` をそのまま許可
2. それ以外は `CORS_ORIGIN` を使用（未設定時は `https://wene-usdc-receipts.pages.dev`）

`CORS_ORIGIN` を明示したい場合:

- **ダッシュボード**: Workers → 該当 Worker → Settings → Variables and Secrets → `CORS_ORIGIN` = `https://<your-domain>`
- **wrangler.toml**: `[vars]` に `CORS_ORIGIN = "https://<your-domain>"` を追加

## ストレージ（Durable Objects）

**Durable Object**（`SchoolStore`）で claims を永続化している。

- `/v1/school/*` のリクエストは Worker から DO に転送され、DO 内の `ctx.storage`（KV）に保存する。
- キー: `claim:${eventId}:${subject}`。**subject** は walletAddress または joinToken を **正規化**（trim・連続空白を1つに）した値。空になった場合は `wallet_required`。
- **同一 subject の 2 回目**は `alreadyJoined: true` を返し、**claimedCount は増えない**。異なる subject なら 1 ずつ増える。
- 集計は `claim:${eventId}:` を prefix に list して件数。eventId ごとに独立（evt-001 と evt-002 は混ざらない）。
- Worker の再起動・デプロイ後も claimedCount と already 判定は維持される。
- ロジックは `src/claimLogic.ts`（`ClaimStore`）、DO は `src/storeDO.ts` でルーティングとストレージアダプタのみ。

### 監査ログの不変保存（運用要件）

- 監査エントリは DO 内ハッシュチェーンに加えて、DO 外の不変シンクに固定化される。
- `AUDIT_IMMUTABLE_MODE=required` の場合、更新系 API（POST/PUT/PATCH/DELETE）は監査固定化が失敗すると 503 で fail-close する。
- `AUDIT_IMMUTABLE_MODE=required` かつ immutable sink が未設定/未準備のときは、更新系 API を**実処理前に 503 で遮断**する（状態変更の先行を防止）。
- production では `AUDIT_LOGS`（R2 バインディング）を必ず設定すること。
- 監査整合性は `GET /api/master/audit-integrity` で定期確認すること。

## テスト

```bash
npm test
```

`test/claimPersistence.test.ts` で「同一 subject で2回 POST しても claimedCount が増えない」「異なる subject なら増える」「joinToken も同様」を検証している。

## 関連

- UI: `wene-mobile`（Cloudflare Pages）
- 契約型: `wene-mobile/src/types/school.ts`
- デプロイメモ: `wene-mobile/docs/CLOUDFLARE_PAGES.md`
