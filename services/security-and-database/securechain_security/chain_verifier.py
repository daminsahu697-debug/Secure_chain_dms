"""
SecureChain DMS — Chain Verifier Service (Module 3)
===================================================
High-level cryptographic integrity verification and forensic audit engine for
the Zero-Trust Digital Evidence Vault (SIH26190).

Legal & Forensic Compliance:
----------------------------
Under Section 65B of the Indian Evidence Act, 1872 and Section 63 of the
Bharatiya Sakshya Adhiniyam (BSA), 2023, electronic records are admissible
in a court of law only when accompanied by an unassailable audit trail
demonstrating that:
  1. The hash chain of custody has remained unbroken since initial seizure.
  2. The raw physical document bytes match the exact hash sealed at registration.
  3. No backdating, deletion, insertion, or unauthorized amendment has occurred.

Security Architecture:
----------------------
1. Two-Tier Verification Workflow:
   - Chain Verification (Forensic Walk): Re-evaluates every link from genesis
     to chain head, checking sequential continuity and recomputing chain digests.
   - Document Content Verification: Re-hashes raw physical document streams
     using streaming SHA-256 and validates against the committed `doc_hash` using
     constant-time comparison (`hmac.compare_digest`).

2. Automated Tamper Alert Generation:
   When any link-level or document-level anomaly is detected, structured
   `TamperAlert` records are produced for immediate ingestion into the WORM
   audit log and dispatched to the court registry notification bus.

3. Court Admissibility Certificate Generation:
   Generates a cryptographically self-verifying "Tamper-Proof Certificate"
   attesting to both chain integrity and document authenticity, suitable for
   presentation to judicial benches and registry officers.

4. Side-Channel Immunity:
   Constant-time comparisons (`hmac.compare_digest`) prevent iterative timing
   leakage during hash verification.

5. Zero Sensitive Data Leakage in Logs:
   Operational metrics, case IDs, and document identifiers are logged. Plaintext
   content, cryptographic keys, and sensitive evidence are never logged.
"""

from __future__ import annotations

import dataclasses
import hmac
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, BinaryIO, Dict, List, Optional, Union

from securechain_security.chain_engine import (
    ChainEngine,
    ChainError,
    ChainNotFoundError,
)
from securechain_security.hash_service import HashService, HashingError
from securechain_security.models import (
    GENESIS_HASH,
    ChainRecord,
    ChainStatus,
    TamperAlert,
    TamperSeverity,
    VerificationResult,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom Exceptions & Data Models
# ---------------------------------------------------------------------------

class VerificationError(Exception):
    """
    Raised when an integrity verification, re-hashing, or certificate generation
    operation encounters an unrecoverable failure.

    Attributes:
        message: Human-readable explanation of the error.
        cause: The underlying exception if this wraps another error, else None.
    """

    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(message)
        self.message = message
        self.cause = cause


@dataclasses.dataclass(frozen=True)
class DocumentVerificationResult:
    """
    Structured outcome of verifying raw physical document content against
    its committed hash in the case's cryptographic chain.
    """
    document_id: str
    case_id: str
    stored_hash: str
    computed_hash: str
    is_match: bool
    timestamp: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Chain Verifier Engine
# ---------------------------------------------------------------------------

class ChainVerifier:
    """
    Forensic Integrity Verification Engine for SecureChain DMS.

    Coordinates on-demand and scheduled audits across per-case hash chains,
    validates raw document byte integrity, generates WORM tamper alerts,
    and produces tamper-proof court admissibility certificates.
    """

    def __init__(
        self,
        chain_engine: Optional[ChainEngine] = None,
        hash_service: Optional[HashService] = None,
    ) -> None:
        """
        Initialize the ChainVerifier.

        Args:
            chain_engine: The case hash chain engine.
            hash_service: Cryptographic hashing service.

        Raises:
            ValueError: If one argument is provided but the other is None.
        """
        if chain_engine is None and hash_service is None:
            hash_service = HashService()
            chain_engine = ChainEngine(hash_service=hash_service)
        elif chain_engine is None:
            raise ValueError("chain_engine cannot be None")
        elif hash_service is None:
            raise ValueError("hash_service cannot be None")

        self._chain_engine: ChainEngine = chain_engine
        self._hash_service: HashService = hash_service
        self._alerts: List[TamperAlert] = []
        self._lock: threading.RLock = threading.RLock()

        logger.info("ChainVerifier initialized successfully")

    def verify_chain(self, chain_records: List[Dict[str, Any]]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Verify an in-memory or database-retrieved list of chain records for sequential continuity.

        Args:
            chain_records: List of version record dictionaries containing chain hashes.

        Returns:
            Tuple of (is_intact: bool, report: List[dict]).
        """
        report: List[Dict[str, Any]] = []
        is_intact = True

        for i, rec in enumerate(chain_records):
            prev_hash = rec.get("prev_chain_hash", "")
            chain_hash = rec.get("chain_hash", "")
            doc_hash = rec.get("doc_hash", "")
            version = rec.get("version_number", f"{i+1}.0")

            if i > 0:
                expected_prev = chain_records[i - 1].get("chain_hash", "")
                if not hmac.compare_digest(prev_hash or "", expected_prev or ""):
                    is_intact = False
                    report.append({
                        "version": version,
                        "status": "FAIL",
                        "reason": f"prev_chain_hash mismatch: expected {expected_prev}, got {prev_hash}"
                    })
                    continue

            report.append({
                "version": version,
                "status": "PASS",
                "chain_hash": chain_hash,
                "doc_hash": doc_hash
            })

        return is_intact, report

    @property
    def chain_engine(self) -> ChainEngine:
        """Return the underlying ChainEngine instance."""
        return self._chain_engine

    @property
    def hash_service(self) -> HashService:
        """Return the underlying HashService instance."""
        return self._hash_service

    @property
    def alerts(self) -> List[TamperAlert]:
        """Return a defensive copy of all generated tamper alerts."""
        with self._lock:
            return list(self._alerts)

    def clear_alerts(self) -> None:
        """Clear recorded tamper alerts from the in-memory log."""
        with self._lock:
            self._alerts.clear()

    def verify_case(self, case_id: str) -> VerificationResult:
        """
        Verify the complete cryptographic chain of custody for a given case.

        Security Rationale:
            Performs a full forensic walk from genesis to chain head. If any
            discontinuity, altered document digest, or corrupted chain link is
            detected, a structured TamperAlert is generated and appended to the
            audit log immediately.

        Args:
            case_id: Case identifier to audit.

        Returns:
            VerificationResult detailing chain status (INTACT, TAMPERED, etc.),
            number of documents checked/valid, and first broken link if any.

        Raises:
            VerificationError: If case_id is invalid or does not exist.
        """
        if not case_id or not isinstance(case_id, str) or not case_id.strip():
            raise VerificationError("case_id must be a non-empty string")

        try:
            result = self._chain_engine.verify_chain_detailed(case_id.strip())
        except ChainNotFoundError as exc:
            raise VerificationError(f"Case '{case_id}' not found in chain engine: {exc}", cause=exc) from exc
        except Exception as exc:
            raise VerificationError(f"Unexpected error auditing case '{case_id}': {exc}", cause=exc) from exc

        if result.status == ChainStatus.TAMPERED:
            alert = self.generate_tamper_report(case_id, result)
            with self._lock:
                self._alerts.append(alert)
            logger.warning(
                "Tamper alert generated for case '%s' (alert_id: %s, broken link: %s)",
                case_id,
                alert.alert_id,
                result.first_broken_link,
            )

        return result

    def verify_document_content(
        self,
        case_id: str,
        document_id: str,
        file_stream_or_bytes: Union[BinaryIO, bytes, bytearray, memoryview, Any],
    ) -> DocumentVerificationResult:
        """
        Verify raw physical document bytes against the committed chain record hash.

        Security Rationale:
            Admissibility under Section 65B / BSA Section 63 requires proving
            that retrieved physical evidence bytes are byte-for-byte identical
            to the evidence seized and sealed at registration.
            Uses constant-time comparison (`hmac.compare_digest`) to prevent
            side-channel timing attacks.

        Args:
            case_id: Case identifier.
            document_id: Document identifier.
            file_stream_or_bytes: Binary file-like object or raw bytes of document.

        Returns:
            DocumentVerificationResult containing stored hash, computed hash,
            and boolean is_match.

        Raises:
            VerificationError: If inputs are invalid or hashing fails.
        """
        if not case_id or not isinstance(case_id, str) or not case_id.strip():
            raise VerificationError("case_id must be a non-empty string")
        if not document_id or not isinstance(document_id, str) or not document_id.strip():
            raise VerificationError("document_id must be a non-empty string")
        if file_stream_or_bytes is None:
            raise VerificationError("file_stream_or_bytes cannot be None")

        # Retrieve the committed chain record
        try:
            record = self._chain_engine.get_document_record(case_id, document_id)
        except ChainNotFoundError as exc:
            raise VerificationError(
                f"Document '{document_id}' not found in case '{case_id}': {exc}",
                cause=exc,
            ) from exc
        except Exception as exc:
            raise VerificationError(
                f"Error retrieving document record for '{document_id}': {exc}",
                cause=exc,
            ) from exc

        # Compute hash of provided content
        try:
            if isinstance(file_stream_or_bytes, (bytes, bytearray, memoryview)):
                computed_hash = self._hash_service.hash_bytes(bytes(file_stream_or_bytes))
            elif hasattr(file_stream_or_bytes, "read") and callable(file_stream_or_bytes.read):
                # Ensure stream position is at start if seekable
                if hasattr(file_stream_or_bytes, "seekable") and callable(file_stream_or_bytes.seekable) and file_stream_or_bytes.seekable():
                    file_stream_or_bytes.seek(0)

                computed_hash = self._hash_service.hash_document(file_stream_or_bytes)

                if hasattr(file_stream_or_bytes, "seekable") and callable(file_stream_or_bytes.seekable) and file_stream_or_bytes.seekable():
                    file_stream_or_bytes.seek(0)
            else:
                raise VerificationError(
                    f"Unsupported content type: {type(file_stream_or_bytes).__name__}. Expected bytes or file stream."
                )
        except HashingError as exc:
            raise VerificationError(f"Hashing failed for document '{document_id}': {exc}", cause=exc) from exc

        # Constant-time comparison
        is_match = hmac.compare_digest(
            computed_hash.lower().strip(),
            record.doc_hash.lower().strip(),
        )

        # If payload tampering is detected, generate CRITICAL alert
        if not is_match:
            alert = TamperAlert(
                alert_id=str(uuid.uuid4()),
                case_id=case_id,
                document_id=document_id,
                severity=TamperSeverity.CRITICAL,
                description=(
                    f"Physical evidence payload mismatch for document '{document_id}' "
                    f"in case '{case_id}'. Content altered since registration."
                ),
                expected_hash=record.doc_hash,
                actual_hash=computed_hash,
                detected_by="on_retrieval",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            with self._lock:
                self._alerts.append(alert)
            logger.critical(
                "CRITICAL TAMPER DETECTED for doc '%s' in case '%s'! Alert ID: %s",
                document_id,
                case_id,
                alert.alert_id,
            )
        else:
            logger.info(
                "Document content verified successfully for doc '%s' in case '%s'",
                document_id,
                case_id,
            )

        return DocumentVerificationResult(
            document_id=document_id,
            case_id=case_id,
            stored_hash=record.doc_hash,
            computed_hash=computed_hash,
            is_match=is_match,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def verify_multiple_cases(self, case_ids: List[str]) -> List[VerificationResult]:
        """
        Perform batch integrity verification across multiple cases.

        Security Rationale:
            Enables periodic registry-wide background audits or automated daily
            sweeps of judicial vaults. Resilient against individual case failures
            so a single corrupt case does not abort the entire audit run.

        Args:
            case_ids: List of case identifiers to audit.

        Returns:
            List of VerificationResult objects corresponding to each case.
        """
        if case_ids is None:
            raise VerificationError("case_ids list cannot be None")

        results: List[VerificationResult] = []

        for cid in case_ids:
            try:
                result = self.verify_case(cid)
            except VerificationError as exc:
                logger.warning("Batch verification failed for case '%s': %s", cid, exc)
                result = VerificationResult(
                    case_id=cid,
                    status=ChainStatus.EMPTY,
                    documents_checked=0,
                    documents_valid=0,
                    error_message=str(exc),
                )
            results.append(result)

        logger.info("Batch verification completed for %d cases", len(results))
        return results

    def generate_tamper_report(
        self,
        case_id: str,
        verification_result: VerificationResult,
    ) -> TamperAlert:
        """
        Generate a detailed TamperAlert model from a failed verification result.

        Security Rationale:
            Provides standardized forensic incident telemetry suitable for
            direct insertion into the WORM audit log, registry notifications,
            and judicial incident reports.

        Args:
            case_id: Case identifier.
            verification_result: Result of the failed chain verification walk.

        Returns:
            TamperAlert dataclass populated with expected vs actual hashes and severity.

        Raises:
            ValueError: If verification_result status is INTACT (no tampering).
        """
        if verification_result.status == ChainStatus.INTACT:
            raise ValueError(
                f"Cannot generate tamper report for case '{case_id}': chain status is INTACT."
            )

        # Inspect broken link in the chain to extract expected vs actual hashes
        expected_hash = ""
        actual_hash = ""
        broken_doc_id = verification_result.first_broken_link or ""

        try:
            chain = self._chain_engine.get_chain(case_id)
            for i, record in enumerate(chain):
                if record.document_id == broken_doc_id:
                    actual_hash = record.chain_hash
                    expected_prev = GENESIS_HASH if i == 0 else chain[i - 1].chain_hash

                    # Recompute what the chain link hash should be
                    expected_hash = self._hash_service.hash_chain_link(
                        doc_hash=record.doc_hash,
                        prev_chain_hash=expected_prev,
                        timestamp=record.timestamp,
                        officer_id=record.officer_id,
                        quorum_token=record.quorum_token,
                    )
                    break
        except Exception as exc:
            logger.debug("Failed to extract broken link hashes for tamper report: %s", exc)

        severity = (
            TamperSeverity.HIGH
            if verification_result.status == ChainStatus.TAMPERED
            else TamperSeverity.MEDIUM
        )

        return TamperAlert(
            alert_id=str(uuid.uuid4()),
            case_id=case_id,
            document_id=broken_doc_id,
            severity=severity,
            description=(
                f"Cryptographic hash chain violation in case '{case_id}': "
                f"{verification_result.error_message or 'Integrity check failed'}"
            ),
            expected_hash=expected_hash,
            actual_hash=actual_hash,
            detected_by="chain_walk",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def generate_court_certificate(
        self,
        case_id: str,
        document_id: str,
        file_stream_or_bytes: Union[BinaryIO, bytes, bytearray, memoryview, Any],
    ) -> Dict[str, Any]:
        """
        Generate a cryptographically self-verifying Tamper-Proof Court Certificate.

        Security Rationale:
            Under Section 65B(4) of the Indian Evidence Act and BSA 2023 Section 63,
            the court requires a formal certificate stating that:
              1. The computer system / evidence vault was operating properly.
              2. The hash chain of custody has unbroken mathematical integrity.
              3. The physical document payload matches the original sealed hash.
            The certificate dictionary incorporates a `certificate_hash` computed
            over its canonical serialized payload to guarantee that the certificate
            itself cannot be forged or altered.

        Args:
            case_id: Case identifier.
            document_id: Document identifier.
            file_stream_or_bytes: Raw bytes or binary stream of the document.

        Returns:
            Dictionary containing case_id, document_id, chain_status,
            content_hash_verified, verification_timestamp, chain_length,
            stored_doc_hash, computed_doc_hash, and certificate_hash.

        Raises:
            VerificationError: If case or document cannot be audited.
        """
        # 1. Audit chain integrity
        chain_res = self.verify_case(case_id)

        # 2. Audit physical document content
        doc_res = self.verify_document_content(case_id, document_id, file_stream_or_bytes)

        # 3. Retrieve chain metadata
        try:
            chain = self._chain_engine.get_chain(case_id)
            chain_length = len(chain)
            record = self._chain_engine.get_document_record(case_id, document_id)
            doc_sequence = record.sequence_number
            doc_version = record.version
            officer_id = record.officer_id
        except Exception as exc:
            raise VerificationError(
                f"Failed to retrieve metadata for court certificate: {exc}", cause=exc
            ) from exc

        timestamp = datetime.now(timezone.utc).isoformat()
        certificate_id = str(uuid.uuid4())

        certificate: Dict[str, Any] = {
            "certificate_id": certificate_id,
            "case_id": case_id,
            "document_id": document_id,
            "chain_status": chain_res.status.value,
            "content_hash_verified": doc_res.is_match,
            "stored_doc_hash": doc_res.stored_hash,
            "computed_doc_hash": doc_res.computed_hash,
            "chain_length": chain_length,
            "sequence_number": doc_sequence,
            "version": doc_version,
            "officer_id": officer_id,
            "verification_timestamp": timestamp,
            "legal_framework": "Section 65B Indian Evidence Act / Section 63 BSA 2023",
            "hash_algorithm": "SHA-256",
        }

        # Canonical self-hash of certificate payload
        canonical_bytes = json.dumps(certificate, sort_keys=True).encode("utf-8")
        certificate["certificate_hash"] = self._hash_service.hash_bytes(canonical_bytes)

        logger.info(
            "Court certificate generated (cert_id: %s, case: %s, doc: %s, valid: %s)",
            certificate_id,
            case_id,
            document_id,
            doc_res.is_match and chain_res.status == ChainStatus.INTACT,
        )
        return certificate

    @staticmethod
    def verify_court_certificate(
        certificate: Dict[str, Any],
        hash_service: Optional[HashService] = None,
    ) -> bool:
        """
        Verify the mathematical integrity of a generated Court Certificate.

        Security Rationale:
            Allows defense attorneys, prosecutors, or judges to independently
            re-hash the certificate dictionary and verify that the `certificate_hash`
            matches, proving the certificate has not been modified after issuance.

        Args:
            certificate: The court certificate dictionary.
            hash_service: Optional HashService instance; defaults to new instance.

        Returns:
            True if the certificate's self-hash matches; False otherwise.
        """
        if not isinstance(certificate, dict) or "certificate_hash" not in certificate:
            return False

        hasher = hash_service if hash_service is not None else HashService()
        expected_cert_hash = certificate["certificate_hash"]

        # Reconstruct canonical payload without certificate_hash
        payload_dict = {k: v for k, v in certificate.items() if k != "certificate_hash"}
        canonical_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
        recomputed_hash = hasher.hash_bytes(canonical_bytes)

        return hmac.compare_digest(
            recomputed_hash.lower().strip(),
            expected_cert_hash.lower().strip(),
        )
