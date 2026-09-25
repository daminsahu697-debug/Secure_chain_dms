"""
SecureChain DMS — Two-Vault Router (Module 6)
=============================================
Enforces cryptographic and physical segregation between Vault 1 (Database)
and Vault 2 (Object Storage) for the Zero-Trust Digital Evidence Vault (SIH26190).

Legal & Forensic Compliance:
----------------------------
Under Section 65B of the Indian Evidence Act, 1872 and Section 63 of the
Bharatiya Sakshya Adhiniyam (BSA), 2023, electronic records presented as judicial
evidence must maintain unimpeachable integrity, non-repudiation, and strict
confidentiality throughout the chain of custody.

Two-Vault Separation Architecture:
----------------------------------
To prevent insider threats, database administrators (DBAs) from reading evidence
payloads, and cloud storage operators from associating or decrypting evidence files,
SecureChain DMS splits every evidence asset into two isolated vaults:

1. Vault 1 (Database / Relational WORM):
   - Stores: Chain records (hash chain links), timestamps, officer identities,
     wrapped DEKs (encrypted under master KEK), Additional Authenticated Data (AAD),
     and SHA-256 doc_hashes.
   - Contains ZERO plaintext document bytes and ZERO raw ciphertext evidence blobs.
   - If Vault 1 is breached, the adversary obtains only metadata, wrapped keys
     (useless without KMS/HSM KEKs), and hashes.

2. Vault 2 (Object Storage / S3 / MinIO):
   - Stores: Purely encrypted evidence blobs (AES-256-GCM ciphertext with appended
     128-bit authentication tag) indexed by deterministic storage references.
   - Contains ZERO metadata, ZERO decryption keys, and ZERO plaintext hashes.
   - If Vault 2 is breached, the adversary obtains only opaque binary blobs with
     no clue what case they belong to or how to decrypt them.

Cryptographic Pipeline:
-----------------------
Upload:
  Plaintext
    │
    ├─► HashService.hash_bytes() ─────────────► doc_hash
    ├─► EncryptionService.encrypt_document() ─► Ciphertext + IV + Wrapped DEK + AAD
    ├─► ChainEngine.create_genesis() / append ─► ChainRecord
    │
    ▼
  VaultPackage:
    ├─► Vault 1: { chain_record, wrapped_dek, aad, doc_hash, iv }
    └─► Vault 2: { ciphertext blob, storage ref: "case/doc/version.enc" }

Retrieval:
  Vault 1 Metadata + Vault 2 Blob
    │
    ├─► Reconstruct WrappedKey, AAD, IV
    ├─► EncryptionService.decrypt_document() ──► Plaintext + Tag Verification
    ├─► Constant-time verification against expected_doc_hash
    │
    ▼
  Verified Plaintext Evidence
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Dict, Optional, Union

from securechain_security.chain_engine import (
    ChainEngine,
    ChainError,
    ChainImmutabilityError,
    ChainNotFoundError,
    QuorumRequiredError,
)
from securechain_security.encryption_service import (
    DecryptionError,
    EncryptionError,
    EncryptionService,
)
from securechain_security.models import (
    IV_LENGTH_BYTES,
    ChainRecord,
    DecryptionResult,
    EncryptionResult,
    VaultPackage,
    VaultTarget,
    WrappedKey,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class VaultRoutingError(Exception):
    """
    Raised when a vault routing, segregation validation, upload, or retrieval operation fails.

    Attributes:
        message: Human-readable error explanation.
        cause: Underlying caught exception, if applicable.
    """

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(message)
        self.message = message
        self.cause = cause


# ---------------------------------------------------------------------------
# Vault Router Implementation
# ---------------------------------------------------------------------------


class VaultRouter:
    """
    Two-Vault Router enforcing strict physical and cryptographic separation between
    Vault 1 (Metadata & Wrapped Keys) and Vault 2 (Encrypted Evidence Blobs).
    """

    def __init__(
        self,
        encryption_service: Optional[EncryptionService] = None,
        chain_engine: Optional[ChainEngine] = None,
    ) -> None:
        """
        Initialize VaultRouter with injected EncryptionService and ChainEngine.

        Security Rationale:
            Dependency injection allows swapping the cryptographic backend (e.g. Cloud KMS
            vs Local KMS) and chain storage backend without altering vault routing rules.

        Args:
            encryption_service: EncryptionService instance. If None, instantiates a default.
            chain_engine: ChainEngine instance. If None, instantiates a default.
        """
        self._encryption_service: EncryptionService = (
            encryption_service if encryption_service is not None else EncryptionService()
        )
        self._chain_engine: ChainEngine = (
            chain_engine
            if chain_engine is not None
            else ChainEngine(hash_service=self._encryption_service.hash_service)
        )

        logger.info("VaultRouter initialized with Two-Vault separation enforcement")

    @property
    def encryption_service(self) -> EncryptionService:
        """Return the underlying EncryptionService instance."""
        return self._encryption_service

    @property
    def chain_engine(self) -> ChainEngine:
        """Return the underlying ChainEngine instance."""
        return self._chain_engine

    @staticmethod
    def generate_blob_reference(case_id: str, document_id: str, version: str) -> str:
        """
        Generate a deterministic storage key / path for Vault 2 (Object Storage).

        Formula:
            ref = f"{case_id}/{document_id}/{version}.enc"

        Security Rationale:
            Deterministic paths allow authorized retrieval workflows to locate the encrypted
            blob in S3 / MinIO object storage given case context, while the blob itself
            remains opaque ciphertext with no embedded metadata.

        Args:
            case_id: Case identifier.
            document_id: Document identifier.
            version: Lifecycle version string.

        Returns:
            Normalized storage path string.

        Raises:
            VaultRoutingError: If any parameter is empty or not a string.
        """
        if not case_id or not isinstance(case_id, str) or not case_id.strip():
            raise VaultRoutingError("case_id must be a non-empty string")
        if not document_id or not isinstance(document_id, str) or not document_id.strip():
            raise VaultRoutingError("document_id must be a non-empty string")
        if not version or not isinstance(version, str) or not version.strip():
            raise VaultRoutingError("version must be a non-empty string")

        return f"{case_id.strip()}/{document_id.strip()}/{version.strip()}.enc"

    def process_upload(
        self,
        plaintext: bytes,
        document_id: str,
        case_id: str,
        officer_id: str,
        version: str = "1.0",
        quorum_token: Optional[str] = None,
        amendment_of: Optional[str] = None,
    ) -> VaultPackage:
        """
        Process an evidence upload through the full cryptographic pipeline and package
        into segregated Vault 1 and Vault 2 payloads.

        Pipeline Stages:
          1. Hash plaintext via `HashService.hash_bytes` to produce canonical `doc_hash`.
          2. Encrypt plaintext via `EncryptionService.encrypt_document` under AES-256-GCM,
             generating unique DEK, unique 96-bit IV, AAD binding, and wrapped DEK.
          3. Anchor or append document to the immutable hash chain via `ChainEngine`:
             - If first document in case: invokes `create_genesis` (sequence 0).
             - Otherwise: invokes `append_document` (sequence N).
          4. Split payload into `VaultPackage`:
             - `vault1_metadata`: {chain_record, wrapped_dek (hex), aad (hex), doc_hash, iv (hex)}.
             - `vault2_blob`: ciphertext bytes.
             - `vault2_blob_ref`: deterministic storage path.

        Args:
            plaintext: Raw document bytes.
            document_id: Unique document identifier.
            case_id: Unique case identifier.
            officer_id: DSC-verified identity of uploading officer.
            version: Version string (default "1.0" for original evidence).
            quorum_token: Multi-signature authorization token (mandatory for amendments v1.1+).
            amendment_of: doc_hash of original document (mandatory for amendments v1.1+).

        Returns:
            VaultPackage dataclass with segregated Vault 1 and Vault 2 payloads.

        Raises:
            VaultRoutingError: If validation, hashing, encryption, or chain anchoring fails.
        """
        if plaintext is None or not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise VaultRoutingError(
                f"Plaintext must be bytes-like, got {type(plaintext).__name__ if plaintext is not None else 'None'}"
            )
        if not document_id or not isinstance(document_id, str) or not document_id.strip():
            raise VaultRoutingError("document_id must be a non-empty string")
        if not case_id or not isinstance(case_id, str) or not case_id.strip():
            raise VaultRoutingError("case_id must be a non-empty string")
        if not officer_id or not isinstance(officer_id, str) or not officer_id.strip():
            raise VaultRoutingError("officer_id must be a non-empty string")
        if not version or not isinstance(version, str) or not version.strip():
            raise VaultRoutingError("version must be a non-empty string")

        clean_doc_id = document_id.strip()
        clean_case_id = case_id.strip()
        clean_officer_id = officer_id.strip()
        clean_version = version.strip()

        logger.info(
            "process_upload: routing upload for document_id=%s, case_id=%s, version=%s",
            clean_doc_id,
            clean_case_id,
            clean_version,
        )

        # Step 1: Compute raw document hash
        try:
            doc_hash = self._encryption_service.hash_service.hash_bytes(bytes(plaintext))
        except Exception as exc:
            logger.error("process_upload: hashing failed for document_id=%s: %s", clean_doc_id, exc)
            raise VaultRoutingError(f"Document hashing failed for '{clean_doc_id}': {exc}", cause=exc) from exc

        # Step 2: Encrypt document with AES-256-GCM envelope encryption
        try:
            enc_res: EncryptionResult = self._encryption_service.encrypt_document(
                plaintext=bytes(plaintext),
                document_id=clean_doc_id,
                case_id=clean_case_id,
                version=clean_version,
                officer_id=clean_officer_id,
            )
        except Exception as exc:
            logger.error("process_upload: encryption failed for document_id=%s: %s", clean_doc_id, exc)
            raise VaultRoutingError(f"Document encryption failed for '{clean_doc_id}': {exc}", cause=exc) from exc

        # Step 3: Anchor into case hash chain (genesis if first, append otherwise)
        try:
            has_chain = False
            try:
                existing_chain = self._chain_engine.get_chain(clean_case_id)
                has_chain = len(existing_chain) > 0
            except ChainNotFoundError:
                has_chain = False

            if not has_chain:
                # First document in case: create genesis record
                if clean_version != "1.0":
                    genesis_hash = amendment_of or "0" * 64
                    self._chain_engine.create_genesis(
                        case_id=clean_case_id,
                        document_id=clean_doc_id,
                        doc_hash=genesis_hash,
                        officer_id=clean_officer_id,
                    )
                    chain_record = self._chain_engine.append_document(
                        case_id=clean_case_id,
                        document_id=clean_doc_id,
                        doc_hash=doc_hash,
                        officer_id=clean_officer_id,
                        version=clean_version,
                        quorum_token=quorum_token,
                        amendment_of=amendment_of,
                    )
                else:
                    chain_record = self._chain_engine.create_genesis(
                        case_id=clean_case_id,
                        document_id=clean_doc_id,
                        doc_hash=doc_hash,
                        officer_id=clean_officer_id,
                    )
            else:
                # Subsequent document or amendment: append to chain
                chain_record = self._chain_engine.append_document(
                    case_id=clean_case_id,
                    document_id=clean_doc_id,
                    doc_hash=doc_hash,
                    officer_id=clean_officer_id,
                    version=clean_version,
                    quorum_token=quorum_token,
                    amendment_of=amendment_of,
                )
        except (ChainError, QuorumRequiredError, ChainImmutabilityError) as exc:
            logger.error("process_upload: chain engine rejected document_id=%s: %s", clean_doc_id, exc)
            raise VaultRoutingError(f"Chain engine rejected document '{clean_doc_id}': {exc}", cause=exc) from exc
        except Exception as exc:
            logger.error("process_upload: unexpected chain error for document_id=%s: %s", clean_doc_id, exc)
            raise VaultRoutingError(f"Unexpected chain error for '{clean_doc_id}': {exc}", cause=exc) from exc

        # Step 4: Build segregated VaultPackage
        blob_ref = self.generate_blob_reference(
            case_id=clean_case_id,
            document_id=clean_doc_id,
            version=clean_version,
        )

        vault1_metadata: Dict[str, Any] = {
            "chain_record": dataclasses.asdict(chain_record),
            "wrapped_dek": enc_res.wrapped_dek.hex(),
            "aad": enc_res.aad.hex(),
            "doc_hash": doc_hash,
            "iv": enc_res.iv.hex(),
            "algorithm": enc_res.algorithm,
        }

        if enc_res.wrapped_key is not None:
            vault1_metadata["kek_version"] = enc_res.wrapped_key.kek_version
            vault1_metadata["key_id"] = enc_res.wrapped_key.key_id

        package = VaultPackage(
            document_id=clean_doc_id,
            case_id=clean_case_id,
            vault1_metadata=vault1_metadata,
            vault1_target=VaultTarget.DATABASE,
            vault2_blob=enc_res.ciphertext,
            vault2_blob_ref=blob_ref,
            vault2_target=VaultTarget.OBJECT_STORAGE,
        )

        logger.info(
            "process_upload completed: document_id=%s, case_id=%s, blob_ref=%s",
            clean_doc_id,
            clean_case_id,
            blob_ref,
        )

        return package

    def process_retrieval(
        self,
        vault1_metadata: dict,
        vault2_blob: bytes,
        expected_doc_hash: str = "",
    ) -> bytes:
        """
        Retrieve and decrypt evidence by recombining Vault 1 metadata with Vault 2 blob.

        Pipeline Stages:
          1. Validates Vault 1 metadata dictionary and Vault 2 blob bytes.
          2. Decodes wrapped DEK, AAD, and IV from hex representations.
          3. Reconstructs `WrappedKey` descriptor.
          4. Decrypts ciphertext blob via `EncryptionService.decrypt_document`.
             AES-GCM authenticates the GHASH tag over both ciphertext and AAD.
          5. Verifies integrity against `expected_doc_hash` (or `vault1_metadata["doc_hash"]`).
          6. Returns authentic plaintext evidence bytes.

        Args:
            vault1_metadata: Dictionary retrieved from Vault 1 (Database).
            vault2_blob: Ciphertext bytes retrieved from Vault 2 (Object Storage).
            expected_doc_hash: Optional SHA-256 hex digest to verify post-decryption integrity.
                               If omitted, defaults to the hash recorded in vault1_metadata.

        Returns:
            Decrypted and integrity-verified plaintext document bytes.

        Raises:
            VaultRoutingError: If metadata is malformed, decryption fails, tag fails,
                             or integrity verification fails.
        """
        if not isinstance(vault1_metadata, dict):
            raise VaultRoutingError(
                f"vault1_metadata must be a dict, got {type(vault1_metadata).__name__}"
            )
        if not isinstance(vault2_blob, (bytes, bytearray, memoryview)):
            raise VaultRoutingError(
                f"vault2_blob must be bytes-like, got {type(vault2_blob).__name__}"
            )

        # Validate presence of required cryptographic fields
        if "wrapped_dek" not in vault1_metadata:
            raise VaultRoutingError("vault1_metadata is missing required key 'wrapped_dek'")
        if "aad" not in vault1_metadata:
            raise VaultRoutingError("vault1_metadata is missing required key 'aad'")

        # Infer document_id from chain_record or AAD
        doc_id = ""
        chain_rec = vault1_metadata.get("chain_record")
        if isinstance(chain_rec, dict):
            doc_id = chain_rec.get("document_id", "")

        logger.info("process_retrieval: reconstructing document_id=%s", doc_id or "unspecified")

        # Decode hex fields from metadata
        try:
            wrapped_dek_bytes = bytes.fromhex(vault1_metadata["wrapped_dek"])
            aad_bytes = bytes.fromhex(vault1_metadata["aad"])
        except ValueError as exc:
            logger.error("process_retrieval: hex decode error for document_id=%s: %s", doc_id, exc)
            raise VaultRoutingError(
                f"Failed to decode hex field in vault1_metadata: {exc}", cause=exc
            ) from exc

        # Extract IV: prefer vault1_metadata["iv"], fallback to packed vault2_blob prefix
        iv_bytes: bytes
        ciphertext_bytes: bytes

        if "iv" in vault1_metadata:
            try:
                iv_bytes = bytes.fromhex(vault1_metadata["iv"])
            except ValueError as exc:
                raise VaultRoutingError(
                    f"Failed to decode 'iv' hex in vault1_metadata: {exc}", cause=exc
                ) from exc
            ciphertext_bytes = bytes(vault2_blob)
        else:
            # Fallback if IV was concatenated into vault2_blob (first 12 bytes)
            if len(vault2_blob) < IV_LENGTH_BYTES:
                raise VaultRoutingError(
                    f"vault2_blob too short ({len(vault2_blob)} bytes) to contain {IV_LENGTH_BYTES}-byte IV"
                )
            iv_bytes = bytes(vault2_blob[:IV_LENGTH_BYTES])
            ciphertext_bytes = bytes(vault2_blob[IV_LENGTH_BYTES:])

        if not doc_id:
            try:
                doc_id = aad_bytes.decode("utf-8", errors="ignore").split(":")[0]
            except Exception:
                doc_id = "unknown"

        # Construct WrappedKey
        kek_version = vault1_metadata.get("kek_version")
        key_id = vault1_metadata.get("key_id", "retrieved-key")
        wrapped_key = WrappedKey(
            key_id=key_id,
            wrapped_dek=wrapped_dek_bytes,
            kek_version=kek_version or self._encryption_service.key_manager.current_kek_version,
            document_id=doc_id,
        )

        # Expected hash for integrity verification
        target_hash = expected_doc_hash or vault1_metadata.get("doc_hash", "")

        # Decrypt via EncryptionService
        try:
            dec_res: DecryptionResult = self._encryption_service.decrypt_document(
                ciphertext=ciphertext_bytes,
                iv=iv_bytes,
                wrapped_dek=wrapped_key,
                aad=aad_bytes,
                expected_doc_hash=target_hash,
                document_id=doc_id,
                strict_integrity=True,
            )
        except DecryptionError as exc:
            logger.error("process_retrieval: decryption failed for document_id=%s: %s", doc_id, exc)
            raise VaultRoutingError(
                f"Decryption failed for document '{doc_id}': {exc}", cause=exc
            ) from exc
        except Exception as exc:
            logger.error("process_retrieval: unexpected error for document_id=%s: %s", doc_id, exc)
            raise VaultRoutingError(
                f"Unexpected error retrieving document '{doc_id}': {exc}", cause=exc
            ) from exc

        # If an explicit expected_doc_hash was supplied, ensure verification succeeded
        if expected_doc_hash and not dec_res.integrity_verified:
            raise VaultRoutingError(
                f"Integrity verification failed for document '{doc_id}': "
                f"computed hash '{dec_res.doc_hash}' does not match expected '{expected_doc_hash}'"
            )

        logger.info(
            "process_retrieval completed: document_id=%s, size=%d bytes, integrity_verified=%s",
            doc_id,
            len(dec_res.plaintext),
            dec_res.integrity_verified,
        )

        return dec_res.plaintext

    def validate_vault_separation(self, vault_package: VaultPackage) -> bool:
        """
        Verify strict Zero-Trust physical and cryptographic isolation in a VaultPackage.

        Separation Invariants:
          1. Vault 1 Metadata Invariants:
             - Contains NO raw ciphertext bytes.
             - Contains NO raw plaintext bytes or strings.
             - Does not contain forbidden keys like 'ciphertext', 'plaintext', 'blob'.
             - Destination target must be VAULT_1_DATABASE.
          2. Vault 2 Blob Invariants:
             - Contains ONLY opaque ciphertext bytes.
             - Contains NO metadata, JSON records, plain keys, or plain SHA-256 hashes.
             - Destination target must be VAULT_2_OBJECT_STORE.

        Args:
            vault_package: The VaultPackage instance to audit.

        Returns:
            bool: True if separation is strictly preserved; False if any crossover occurs.
        """
        if not isinstance(vault_package, VaultPackage):
            logger.warning("validate_vault_separation: input is not a VaultPackage instance")
            return False

        # 1. Verify routing target enums
        if vault_package.vault1_target != VaultTarget.DATABASE:
            logger.warning(
                "validate_vault_separation: vault1_target is '%s', expected '%s'",
                vault_package.vault1_target,
                VaultTarget.DATABASE,
            )
            return False

        if vault_package.vault2_target != VaultTarget.OBJECT_STORAGE:
            logger.warning(
                "validate_vault_separation: vault2_target is '%s', expected '%s'",
                vault_package.vault2_target,
                VaultTarget.OBJECT_STORAGE,
            )
            return False

        v1_meta = vault_package.vault1_metadata
        v2_blob = vault_package.vault2_blob

        if not isinstance(v1_meta, dict) or not isinstance(v2_blob, (bytes, bytearray, memoryview)):
            logger.warning("validate_vault_separation: invalid payload types")
            return False

        # 2. Check Vault 1 metadata: must contain NO ciphertext or plaintext
        forbidden_v1_keys = {
            "ciphertext",
            "plaintext",
            "blob",
            "vault2_blob",
            "raw_payload",
            "content",
        }
        for k in v1_meta.keys():
            if str(k).lower() in forbidden_v1_keys:
                logger.warning(
                    "validate_vault_separation: Vault 1 metadata contains forbidden key '%s'",
                    k,
                )
                return False

        # If v2_blob is non-empty, ensure it does not appear anywhere inside Vault 1
        if len(v2_blob) > 0:
            blob_bytes = bytes(v2_blob)
            blob_hex = blob_bytes.hex()

            for k, val in v1_meta.items():
                # Direct equality check
                if val == blob_bytes or val == blob_hex:
                    logger.warning(
                        "validate_vault_separation: Vault 1 metadata field '%s' contains Vault 2 blob",
                        k,
                    )
                    return False

        # 3. Check Vault 2 blob: must contain NO metadata, keys, or hashes in plaintext
        # Check that doc_hash (64 hex characters) is not in v2_blob as ASCII text
        doc_hash = str(v1_meta.get("doc_hash", "")).strip()
        if len(doc_hash) == 64:
            if doc_hash.encode("ascii") in v2_blob:
                logger.warning(
                    "validate_vault_separation: Vault 2 blob contains plaintext doc_hash"
                )
                return False

        # Check that JSON metadata markers do not appear in v2_blob
        forbidden_plaintext_markers = [
            b'"chain_record"',
            b'"prev_chain_hash"',
            b'"officer_id"',
            b'"wrapped_dek"',
        ]
        for marker in forbidden_plaintext_markers:
            if marker in v2_blob:
                logger.warning(
                    "validate_vault_separation: Vault 2 blob contains plaintext marker '%s'",
                    marker.decode("ascii", errors="ignore"),
                )
                return False

        logger.debug(
            "validate_vault_separation: separation cleanly validated for document_id=%s",
            vault_package.document_id,
        )
        return True
