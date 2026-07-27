import type { KeyboundP256PublicKey } from "./types.js";

const DEFAULT_DB_NAME = "keybound";
const DEFAULT_STORE_NAME = "device-keys";
const DEFAULT_KEY_NAME = "default";
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const CHALLENGE_BYTES = 32;

export interface KeyboundBrowserOptions {
  readonly dbName?: string;
  readonly storeName?: string;
  readonly keyName?: string;
}

export interface KeyboundBrowserRuntime {
  readonly crypto?: {
    readonly subtle?: SubtleCrypto;
  };
  readonly indexedDB?: IDBFactory;
}

export interface KeyboundBrowserDeviceKey {
  readonly publicKey: KeyboundP256PublicKey;
  readonly created: boolean;
  signChallenge(challenge: string): Promise<string>;
  clear(): Promise<void>;
}

export type KeyboundBrowserErrorReason =
  | "not-supported"
  | "not-allowed"
  | "invalid-access"
  | "data-error"
  | "operation-error"
  | "unknown";

export interface KeyboundBrowserErrorDescription {
  readonly ok: false;
  readonly reason: KeyboundBrowserErrorReason;
  readonly name: string;
  readonly message: string;
}

interface NormalizedOptions {
  readonly dbName: string;
  readonly storeName: string;
  readonly keyName: string;
}

interface StoredKeyPair {
  readonly publicKey: CryptoKey;
  readonly privateKey: CryptoKey;
}

export function isKeyboundBrowserSupported(
  runtime: KeyboundBrowserRuntime = globalThis
): boolean {
  return Boolean(runtime.crypto?.subtle && runtime.indexedDB);
}

export async function getOrCreateKeyboundBrowserKey(
  options: KeyboundBrowserOptions = {}
): Promise<KeyboundBrowserDeviceKey> {
  assertBrowserSupport();

  const normalized = normalizeOptions(options);
  const db = await openDatabase(normalized);

  try {
    const stored = await readStoredKeyPair(db, normalized);
    if (stored) {
      return createDeviceKey(stored, normalized, false);
    }

    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    );
    const storedPair = pair as StoredKeyPair;
    await writeStoredKeyPair(db, normalized, storedPair);

    return createDeviceKey(storedPair, normalized, true);
  } finally {
    db.close();
  }
}

export async function getKeyboundBrowserPublicKey(
  options: KeyboundBrowserOptions = {}
): Promise<KeyboundP256PublicKey | null> {
  assertBrowserSupport();

  const normalized = normalizeOptions(options);
  const db = await openDatabase(normalized);

  try {
    const stored = await readStoredKeyPair(db, normalized);
    return stored ? exportPublicKey(stored.publicKey) : null;
  } finally {
    db.close();
  }
}

export async function signKeyboundChallenge(
  challenge: string,
  options: KeyboundBrowserOptions = {}
): Promise<string> {
  const deviceKey = await getOrCreateKeyboundBrowserKey(options);
  return deviceKey.signChallenge(challenge);
}

export async function clearKeyboundBrowserKey(
  options: KeyboundBrowserOptions = {}
): Promise<void> {
  assertBrowserSupport();

  const normalized = normalizeOptions(options);
  const db = await openDatabase(normalized);

  try {
    await deleteStoredKeyPair(db, normalized);
  } finally {
    db.close();
  }
}

export function describeKeyboundBrowserError(
  error: unknown
): KeyboundBrowserErrorDescription {
  const name =
    error && typeof error === "object" && "name" in error
      ? String(error.name)
      : "Error";

  switch (name) {
    case "NotSupportedError":
      return describe("not-supported", name, "Browser key storage is not available.");
    case "NotAllowedError":
      return describe("not-allowed", name, "The browser refused this key operation.");
    case "InvalidAccessError":
      return describe(
        "invalid-access",
        name,
        "The stored key cannot be used for this proof."
      );
    case "DataError":
      return describe("data-error", name, "The key or challenge data is malformed.");
    case "OperationError":
      return describe("operation-error", name, "The browser crypto operation failed.");
    default:
      return describe("unknown", name, "Browser proof failed.");
  }
}

async function createDeviceKey(
  pair: StoredKeyPair,
  options: NormalizedOptions,
  created: boolean
): Promise<KeyboundBrowserDeviceKey> {
  const publicKey = await exportPublicKey(pair.publicKey);

  return Object.freeze({
    publicKey,
    created,
    async signChallenge(challenge: string): Promise<string> {
      const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        pair.privateKey,
        decodeChallenge(challenge)
      );

      return toBase64url(signature);
    },
    async clear(): Promise<void> {
      await clearKeyboundBrowserKey(options);
    }
  });
}

async function exportPublicKey(key: CryptoKey): Promise<KeyboundP256PublicKey> {
  const publicKey = await crypto.subtle.exportKey("jwk", key);

  if (
    publicKey.kty !== "EC" ||
    publicKey.crv !== "P-256" ||
    typeof publicKey.x !== "string" ||
    typeof publicKey.y !== "string"
  ) {
    throw new TypeError("Keybound browser public key must be an EC P-256 JWK.");
  }

  return Object.freeze({
    kty: "EC",
    crv: "P-256",
    x: publicKey.x,
    y: publicKey.y
  });
}

function assertBrowserSupport(): void {
  if (!isKeyboundBrowserSupported()) {
    throw new DOMException(
      "Keybound requires Web Crypto and IndexedDB in the browser.",
      "NotSupportedError"
    );
  }
}

async function openDatabase(options: NormalizedOptions): Promise<IDBDatabase> {
  const first = await openDatabaseVersion(options, undefined);
  if (first.objectStoreNames.contains(options.storeName)) {
    return first;
  }

  const nextVersion = first.version + 1;
  first.close();
  return openDatabaseVersion(options, nextVersion);
}

function openDatabaseVersion(
  options: NormalizedOptions,
  version: number | undefined
): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request =
      typeof version === "number"
        ? indexedDB.open(options.dbName, version)
        : indexedDB.open(options.dbName);

    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(options.storeName)) {
        request.result.createObjectStore(options.storeName);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => {
      reject(
        new DOMException(
          "Keybound browser key database is blocked by another tab.",
          "OperationError"
        )
      );
    };
  });
}

function readStoredKeyPair(
  db: IDBDatabase,
  options: NormalizedOptions
): Promise<StoredKeyPair | null> {
  return new Promise((resolve, reject) => {
    const request = db
      .transaction(options.storeName, "readonly")
      .objectStore(options.storeName)
      .get(options.keyName);

    request.onsuccess = () => {
      const value = request.result;
      resolve(isStoredKeyPair(value) ? value : null);
    };
    request.onerror = () => reject(request.error);
  });
}

function writeStoredKeyPair(
  db: IDBDatabase,
  options: NormalizedOptions,
  pair: StoredKeyPair
): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(options.storeName, "readwrite");
    tx.objectStore(options.storeName).put(pair, options.keyName);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function deleteStoredKeyPair(
  db: IDBDatabase,
  options: NormalizedOptions
): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(options.storeName, "readwrite");
    tx.objectStore(options.storeName).delete(options.keyName);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function isStoredKeyPair(value: unknown): value is StoredKeyPair {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const record = value as Partial<StoredKeyPair>;

  return (
    record.publicKey instanceof CryptoKey &&
    record.privateKey instanceof CryptoKey
  );
}

function normalizeOptions(options: KeyboundBrowserOptions): NormalizedOptions {
  const dbName = options.dbName ?? DEFAULT_DB_NAME;
  const storeName = options.storeName ?? DEFAULT_STORE_NAME;
  const keyName = options.keyName ?? DEFAULT_KEY_NAME;

  assertStorageName(dbName, "dbName");
  assertStorageName(storeName, "storeName");
  assertStorageName(keyName, "keyName");

  return { dbName, storeName, keyName };
}

function assertStorageName(value: string, name: string): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 128 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`Keybound browser ${name} is invalid.`);
  }
}

function decodeChallenge(value: string): ArrayBuffer {
  if (typeof value !== "string" || !BASE64URL.test(value)) {
    throw new TypeError("Keybound challenge must be base64url.");
  }

  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  if (bytes.length !== CHALLENGE_BYTES) {
    throw new TypeError("Keybound challenge has an invalid length.");
  }

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes.buffer;
}

function toBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function describe(
  reason: KeyboundBrowserErrorReason,
  name: string,
  message: string
): KeyboundBrowserErrorDescription {
  return Object.freeze({ ok: false, reason, name, message });
}
