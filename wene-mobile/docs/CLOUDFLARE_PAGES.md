# Cloudflare Pages デプロイ（固定HTTPS）

学校PoCを「当日運用できる」状態にするための、Cloudflare Pages での Web ホスト設定メモ。再現性のため環境変数と設定を固定する。

## プロジェクト設定

| 項目 | 値 |
|------|-----|
| **Root directory** | `wene-mobile` |
| **Build command** | `npm ci && npm run export:web` |
| **Output directory** | `dist` |

## 環境変数

| 変数 | 値 | 備考 |
|------|-----|------|
| `EXPO_PUBLIC_BASE_URL` | `https://<your-pages-domain>` | 末尾スラッシュなし。印刷QRのベースURLになる |
| `EXPO_PUBLIC_API_MODE` | `mock` または `http` | 本番は `http`（Workers API に接続） |
| `EXPO_PUBLIC_API_BASE_URL` | `https://wene-usdc-receipts-api.haruki-kira3.workers.dev` | **http モード時必須**。Cloudflare Workers API のベースURL（末尾スラッシュなし） |

### Pages + Workers で運用する場合

- **Pages** の環境変数に上記3つを設定する。
- **Workers**（`api-worker/`）を別途デプロイし、`https://wene-usdc-receipts-api.haruki-kira3.workers.dev` を `EXPO_PUBLIC_API_BASE_URL` に指定する。
- Workers 側で CORS に Pages のドメイン（`EXPO_PUBLIC_BASE_URL`）を許可する（`CORS_ORIGIN` 変数）。

これにより、ローカルサーバなしで Pages 上の UI が Workers API からイベント一覧・claim を取得できる。

## 確認（直アクセスが 404 にならないこと）

次の3URLを直アクセスして、いずれも 404 にならないことを確認する。

1. `https://<domain>/admin`
2. `https://<domain>/admin/print/evt-001`
3. `https://<domain>/u/confirm?eventId=evt-001`

`dist/_redirects` は **静的ファイルのパススルーを先に置いた上で** `/* /index.html 200` が最後にあることを確認する。  
（`/assets/*` や `/_expo/*` が先にないと、画像/フォント要求が `index.html` に書き換わって表示崩れの原因になる）

## 関連

* README_SCHOOL.md の「Cloudflare Pages でのデプロイ」「デプロイURLでの最終確認」も参照。
