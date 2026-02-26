import { BN } from '@coral-xyz/anchor';
import {
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_RENT_PUBKEY,
  Transaction,
  TransactionInstruction,
} from '@solana/web3.js';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  AuthorityType,
  MINT_SIZE,
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountInstruction,
  createInitializeMintInstruction,
  createMintToInstruction,
  createSetAuthorityInstruction,
  getAssociatedTokenAddressSync,
} from '@solana/spl-token';
import {
  PROGRAM_ID as TOKEN_METADATA_PROGRAM_ID,
  createCreateMetadataAccountV3Instruction,
} from '@metaplex-foundation/mpl-token-metadata';
import { GRANT_PROGRAM_ID } from './config';
import { getConnection, getProgram } from './anchorClient';
import { getGrantPda, getPopConfigPda, getVaultPda } from './grantProgram';
import { signTransaction } from '../utils/phantom';
import { createSimulationFailedError, sendSignedTx, isSimulationFailedError } from './sendTx';
import { setPhantomWebReturnPath } from '../utils/phantomWebReturnPath';
import type { PhantomExtensionProvider } from '../wallet/phantomExtension';

const MAX_U64 = (BigInt(1) << BigInt(64)) - BigInt(1);
const MIN_PREFUND_MULTIPLIER = 100;
const UPSERT_POP_CONFIG_DISCRIMINATOR = Buffer.from([103, 79, 37, 9, 166, 255, 209, 132]);

interface AdminPhantomMobileContext {
  mode: 'mobile';
  walletPubkey: string;
  phantomSession: string;
  dappEncryptionPublicKey: string;
  dappSecretKey: Uint8Array;
  phantomEncryptionPublicKey: string;
}

interface AdminPhantomExtensionContext {
  mode: 'extension';
  walletPubkey: string;
  extensionProvider: PhantomExtensionProvider;
}

export type AdminPhantomContext =
  | AdminPhantomMobileContext
  | AdminPhantomExtensionContext;

export interface IssueEventTicketTokenParams {
  phantom: AdminPhantomContext;
  eventTitle: string;
  ticketTokenAmount: number;
  claimIntervalDays: number;
  maxClaimsPerInterval: number | null;
}

export interface IssueEventTicketTokenResult {
  solanaMint: string;
  solanaAuthority: string;
  solanaGrantId: string;
  amountPerPeriod: string;
  bootstrapMintAmount: string;
  adminRetainedAmount: string;
  mintDecimals: number;
  setupSignatures: string[];
}

function buildSignRedirectContext(): { redirectLink: string; appUrl: string } {
  if (typeof window !== 'undefined' && window.location?.origin) {
    const returnPath = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    setPhantomWebReturnPath(returnPath);
    return {
      redirectLink: `${window.location.origin}/phantom/signTransaction`,
      appUrl: window.location.origin,
    };
  }
  return {
    redirectLink: 'wene://phantom/sign?cluster=devnet',
    appUrl: 'https://wene.app',
  };
}

function toU64(value: bigint, name: string): bigint {
  if (value <= BigInt(0)) {
    throw new Error(`${name} must be greater than 0`);
  }
  if (value > MAX_U64) {
    throw new Error(`${name} exceeds u64 limit`);
  }
  return value;
}

function computeBootstrapAmount(
  amountPerPeriod: bigint,
  maxClaimsPerInterval: number | null
): bigint {
  const expectedClaimsPerInterval = maxClaimsPerInterval == null
    ? 100
    : Math.max(1, Math.floor(maxClaimsPerInterval));
  const expectedIntervals = maxClaimsPerInterval == null ? 30 : 60;
  const base = amountPerPeriod * BigInt(expectedClaimsPerInterval) * BigInt(expectedIntervals);
  const floor = amountPerPeriod * BigInt(MIN_PREFUND_MULTIPLIER);
  return base > floor ? base : floor;
}

function clipUtf8(input: string, maxBytes: number): string {
  if (maxBytes <= 0) return '';
  let out = '';
  let used = 0;
  for (const ch of input) {
    const bytes = new TextEncoder().encode(ch).length;
    if (used + bytes > maxBytes) break;
    out += ch;
    used += bytes;
  }
  return out;
}

function resolveMetadataBaseUrl(): string {
  const envBase = (
    process.env.EXPO_PUBLIC_API_BASE_URL ??
    process.env.EXPO_PUBLIC_SCHOOL_API_BASE_URL ??
    ''
  ).trim().replace(/\/$/, '');
  if (typeof window !== 'undefined' && window.location?.origin) {
    if (envBase && !isLocalBaseUrl(envBase)) {
      return envBase;
    }
    return window.location.origin.replace(/\/$/, '');
  }
  if (envBase) return envBase;
  return 'https://wene-usdc-receipts-api.haruki-kira3.workers.dev';
}

function isLocalBaseUrl(raw: string): boolean {
  try {
    const url = new URL(raw);
    return (
      url.hostname === 'localhost' ||
      url.hostname === '127.0.0.1' ||
      url.hostname === '0.0.0.0' ||
      url.hostname === '::1'
    );
  } catch {
    const normalized = raw.toLowerCase();
    return (
      normalized.startsWith('http://localhost') ||
      normalized.startsWith('https://localhost') ||
      normalized.startsWith('http://127.0.0.1') ||
      normalized.startsWith('https://127.0.0.1')
    );
  }
}

function normalizePubkeyString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

async function fetchPopSignerPubkeyFromRuntime(baseUrl: string): Promise<string | null> {
  const runtimeStatusUrl = `${baseUrl}/v1/school/runtime-status`;
  try {
    const runtimeRes = await fetch(runtimeStatusUrl, { method: 'GET' });
    if (runtimeRes.ok) {
      const runtime = (await runtimeRes.json()) as {
        checks?: { popSignerPubkey?: string | null };
      };
      const runtimePubkey = normalizePubkeyString(runtime?.checks?.popSignerPubkey);
      if (runtimePubkey) return runtimePubkey;
    }
  } catch {
    // no-op: fallback to pop-status
  }

  const popStatusUrl = `${baseUrl}/v1/school/pop-status`;
  try {
    const popRes = await fetch(popStatusUrl, { method: 'GET' });
    if (!popRes.ok) return null;
    const pop = (await popRes.json()) as { signerPubkey?: string | null };
    return normalizePubkeyString(pop?.signerPubkey);
  } catch {
    return null;
  }
}

async function resolvePopSignerPubkey(): Promise<PublicKey> {
  const envRaw = normalizePubkeyString(process.env.EXPO_PUBLIC_POP_SIGNER_PUBKEY);
  const runtimeRaw = envRaw ? null : await fetchPopSignerPubkeyFromRuntime(resolveMetadataBaseUrl());
  const raw = envRaw ?? runtimeRaw;
  if (!raw) {
    throw new Error(
      'PoP署名者公開鍵が未設定です。EXPO_PUBLIC_POP_SIGNER_PUBKEY を設定するか、runtime-status で popSignerPubkey を返してください'
    );
  }
  try {
    return new PublicKey(raw);
  } catch {
    throw new Error(
      `PoP署名者公開鍵の形式が不正です: ${raw}. EXPO_PUBLIC_POP_SIGNER_PUBKEY または runtime-status の値を確認してください`
    );
  }
}

function buildUpsertPopConfigInstruction(params: {
  authority: PublicKey;
  popConfigPda: PublicKey;
  signerPubkey: PublicKey;
}): TransactionInstruction {
  const data = Buffer.alloc(8 + 32);
  UPSERT_POP_CONFIG_DISCRIMINATOR.copy(data, 0);
  params.signerPubkey.toBuffer().copy(data, 8);
  return new TransactionInstruction({
    programId: GRANT_PROGRAM_ID,
    keys: [
      { pubkey: params.popConfigPda, isSigner: false, isWritable: true },
      { pubkey: params.authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false },
    ],
    data,
  });
}

function hasFallbackNotFoundSignal(text: string): boolean {
  const normalized = text.toLowerCase();
  return (
    normalized.includes('instructionfallbacknotfound') ||
    normalized.includes('fallback functions are not supported') ||
    normalized.includes('custom program error: 0x65')
  );
}

function isUnsupportedUpsertPopConfigError(error: unknown): boolean {
  const msg = error instanceof Error ? error.message : String(error ?? '');
  if (hasFallbackNotFoundSignal(msg)) return true;
  if (isSimulationFailedError(error)) {
    const logs = Array.isArray(error.simLogs) ? error.simLogs : [];
    return logs.some((line) => hasFallbackNotFoundSignal(String(line)));
  }
  return false;
}

function shouldAttemptPopConfigUpsert(): boolean {
  const raw = (process.env.EXPO_PUBLIC_ENABLE_POP_CONFIG_UPSERT ?? '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

function wrapSetupStepError(step: string, error: unknown): never {
  if (isSimulationFailedError(error)) {
    throw createSimulationFailedError(
      `[${step}] ${error.message}`,
      error.simErr,
      error.simLogs ?? null,
      error.unitsConsumed
    );
  }
  const msg = error instanceof Error ? error.message : String(error ?? 'unknown error');
  throw new Error(`[${step}] ${msg}`);
}

async function signAndSendTx(
  tx: Transaction,
  phantom: AdminPhantomContext,
  extraSigners: Keypair[] = []
): Promise<string> {
  const connection = getConnection();
  const feePayer = new PublicKey(phantom.walletPubkey);
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
  tx.recentBlockhash = blockhash;
  tx.feePayer = feePayer;
  if (extraSigners.length > 0) {
    tx.partialSign(...extraSigners);
  }

  let signedTx: Transaction;
  if (phantom.mode === 'extension') {
    const provider = phantom.extensionProvider;
    if (!provider.isConnected) {
      await provider.connect();
    }
    signedTx = await provider.signTransaction(tx);
  } else {
    const { redirectLink, appUrl } = buildSignRedirectContext();
    signedTx = await signTransaction({
      tx,
      session: phantom.phantomSession,
      dappEncryptionPublicKey: phantom.dappEncryptionPublicKey,
      dappSecretKey: phantom.dappSecretKey,
      phantomEncryptionPublicKey: phantom.phantomEncryptionPublicKey,
      redirectLink,
      cluster: 'devnet',
      appUrl,
    });
  }
  return sendSignedTx(signedTx, { blockhash, lastValidBlockHeight });
}

export async function issueEventTicketToken(
  params: IssueEventTicketTokenParams
): Promise<IssueEventTicketTokenResult> {
  const amountPerPeriod = toU64(BigInt(Math.floor(params.ticketTokenAmount)), 'ticketTokenAmount');
  const bootstrapAmount = toU64(
    computeBootstrapAmount(amountPerPeriod, params.maxClaimsPerInterval),
    'bootstrapMintAmount'
  );
  const adminRetainedAmount = BigInt(1);
  const initialMintAmount = toU64(
    bootstrapAmount + adminRetainedAmount,
    'initialMintAmount'
  );

  const mintDecimals = 0;
  const claimIntervalDays = Math.max(1, Math.floor(params.claimIntervalDays));
  const periodSeconds = toU64(BigInt(claimIntervalDays * 24 * 60 * 60), 'periodSeconds');

  const authority = new PublicKey(params.phantom.walletPubkey);
  const popSignerPubkey = await resolvePopSignerPubkey();
  const mintKeypair = Keypair.generate();
  const mint = mintKeypair.publicKey;
  const grantId = BigInt(Date.now() * 1000 + Math.floor(Math.random() * 1000));
  const metadataName = clipUtf8(params.eventTitle.trim() || 'Event Ticket', 32);
  const metadataSymbol = clipUtf8((params.eventTitle || 'TICKET').replace(/\s+/g, '').slice(0, 10), 10) || 'TICKET';
  const metadataUri = clipUtf8(`${resolveMetadataBaseUrl()}/metadata/${mint.toBase58()}.json`, 200);

  const ownerAta = getAssociatedTokenAddressSync(
    mint,
    authority,
    false,
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID
  );
  const [grantPda] = getGrantPda(authority, mint, grantId);
  const [vaultPda] = getVaultPda(grantPda);
  const [popConfigPda] = getPopConfigPda(authority);
  const [metadataPda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from('metadata'),
      TOKEN_METADATA_PROGRAM_ID.toBuffer(),
      mint.toBuffer(),
    ],
    TOKEN_METADATA_PROGRAM_ID
  );
  const setupSignatures: string[] = [];
  const popConfigUpsertEnabled = shouldAttemptPopConfigUpsert();

  // Tx0: PoP設定（デフォルト無効。必要時のみ有効化）
  // EXPO_PUBLIC_ENABLE_POP_CONFIG_UPSERT=true の場合のみ実行。
  if (popConfigUpsertEnabled) {
    const upsertPopConfigIx = buildUpsertPopConfigInstruction({
      authority,
      popConfigPda,
      signerPubkey: popSignerPubkey,
    });
    const tx0 = new Transaction().add(upsertPopConfigIx);
    try {
      setupSignatures.push(await signAndSendTx(tx0, params.phantom));
    } catch (error) {
      if (isUnsupportedUpsertPopConfigError(error)) {
        console.warn('[issueEventTicketToken] upsert_pop_config unsupported on deployed program; continue without pop-config upsert');
      } else {
        wrapSetupStepError('tx0-pop-config', error);
      }
    }
  } else {
    console.warn('[issueEventTicketToken] pop-config upsert skipped (EXPO_PUBLIC_ENABLE_POP_CONFIG_UPSERT is not enabled)');
  }

  // Tx1: 新規mint作成 + admin ATA作成 + 初期供給mint
  {
    try {
      const connection = getConnection();
      const rentForMint = await connection.getMinimumBalanceForRentExemption(MINT_SIZE, 'confirmed');
      const tx1 = new Transaction();
      tx1.add(
        SystemProgram.createAccount({
          fromPubkey: authority,
          newAccountPubkey: mint,
          lamports: rentForMint,
          space: MINT_SIZE,
          programId: TOKEN_PROGRAM_ID,
        }),
        createInitializeMintInstruction(
          mint,
          mintDecimals,
          authority,
          authority,
          TOKEN_PROGRAM_ID
        ),
        createAssociatedTokenAccountInstruction(
          authority,
          ownerAta,
          authority,
          mint,
          TOKEN_PROGRAM_ID,
          ASSOCIATED_TOKEN_PROGRAM_ID
        ),
        createMintToInstruction(
          mint,
          ownerAta,
          authority,
          initialMintAmount,
          [],
          TOKEN_PROGRAM_ID
        )
      );
      setupSignatures.push(await signAndSendTx(tx1, params.phantom, [mintKeypair]));
    } catch (error) {
      wrapSetupStepError('tx1-mint-bootstrap', error);
    }
  }

  // Tx2: Grant作成 + Vaultへ初期入金
  {
    try {
      const program = getProgram() as any;
      const nowTs = Math.floor(Date.now() / 1000);
      const startTs = Math.max(0, nowTs - 120);

      const createGrantIx = await program.methods
        .createGrant(
          new BN(grantId.toString()),
          new BN(amountPerPeriod.toString()),
          new BN(periodSeconds.toString()),
          new BN(startTs.toString()),
          new BN('0')
        )
        .accounts({
          grant: grantPda,
          mint,
          vault: vaultPda,
          authority,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: SystemProgram.programId,
          rent: SYSVAR_RENT_PUBKEY,
        })
        .instruction();

      const fundGrantIx = await program.methods
        .fundGrant(new BN(bootstrapAmount.toString()))
        .accounts({
          grant: grantPda,
          mint,
          vault: vaultPda,
          fromAta: ownerAta,
          funder: authority,
          authority,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .instruction();

      const tx2 = new Transaction().add(
        createGrantIx,
        fundGrantIx
      );
      setupSignatures.push(await signAndSendTx(tx2, params.phantom));
    } catch (error) {
      wrapSetupStepError('tx2-create-grant-and-fund', error);
    }
  }

  // Tx3: Metadata作成（txサイズ/compute負荷を抑えるため分離）
  {
    try {
      const metadataIx = createCreateMetadataAccountV3Instruction(
        {
          metadata: metadataPda,
          mint,
          mintAuthority: authority,
          payer: authority,
          updateAuthority: authority,
        },
        {
          createMetadataAccountArgsV3: {
            data: {
              name: metadataName,
              symbol: metadataSymbol,
              uri: metadataUri,
              sellerFeeBasisPoints: 0,
              creators: null,
              collection: null,
              uses: null,
            },
            isMutable: true,
            collectionDetails: null,
          },
        },
        TOKEN_METADATA_PROGRAM_ID
      );

      const tx3 = new Transaction().add(metadataIx);
      setupSignatures.push(await signAndSendTx(tx3, params.phantom));
    } catch (error) {
      wrapSetupStepError('tx3-create-metadata', error);
    }
  }

  // Tx4: mint/freeze authority を放棄（最終確定）
  {
    try {
      const revokeMintAuthorityIx = createSetAuthorityInstruction(
        mint,
        authority,
        AuthorityType.MintTokens,
        null,
        [],
        TOKEN_PROGRAM_ID
      );

      const revokeFreezeAuthorityIx = createSetAuthorityInstruction(
        mint,
        authority,
        AuthorityType.FreezeAccount,
        null,
        [],
        TOKEN_PROGRAM_ID
      );

      const tx4 = new Transaction().add(
        revokeMintAuthorityIx,
        revokeFreezeAuthorityIx
      );
      setupSignatures.push(await signAndSendTx(tx4, params.phantom));
    } catch (error) {
      wrapSetupStepError('tx4-revoke-authorities', error);
    }
  }

  return {
    solanaMint: mint.toBase58(),
    solanaAuthority: authority.toBase58(),
    solanaGrantId: grantId.toString(),
    amountPerPeriod: amountPerPeriod.toString(),
    bootstrapMintAmount: bootstrapAmount.toString(),
    adminRetainedAmount: adminRetainedAmount.toString(),
    mintDecimals,
    setupSignatures,
  };
}
