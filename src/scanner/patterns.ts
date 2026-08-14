/**
 * Security-relevant patterns shared by the static scanner and the runtime
 * sentinel. Single source of truth — keep both layers matching the same
 * credential vocabulary.
 * @module dsh-plugin-audit/scanner/patterns
 */

/** Env var names that look credential-bearing. */
export const SENSITIVE_ENV = /TOKEN|KEY|SECRET|PASSW|CREDENTIAL|AUTH|COOKIE|SESSION/i

/** Path fragments that usually hold credentials or identities. */
export const CREDENTIAL_PATH = /(\.ssh|\.aws|\.gnupg|\.git-credentials|\.netrc|\.npmrc|id_rsa|id_ed25519|keychain|\.docker\/config\.json)/i
