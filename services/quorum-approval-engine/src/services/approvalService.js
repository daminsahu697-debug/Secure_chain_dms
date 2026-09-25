const crypto = require('crypto');
const { getTierConfig } = require('../config/sensitivity');
const AnonymityService = require('./anonymityService');
const AuditService = require('./auditService');

class ApprovalService {
  constructor(db) {
    this.db = db;
    this.auditService = new AuditService(db);
  }

  /**
   * Calculate next sub-version number (e.g., "1.0" -> "1.1", "2.1" -> "2.2")
   */
  _bumpVersion(currentVersion) {
    const parts = (currentVersion || '1.0').split('.');
    const major = parts[0] || '1';
    const minor = parseInt(parts[1] || '0', 10) + 1;
    return `${major}.${minor}`;
  }

  /**
   * Helper error generator
   */
  _createError(message, statusCode, code) {
    const error = new Error(message);
    error.statusCode = statusCode;
    error.code = code;
    return error;
  }

  /**
   * Creates a new Document Edit Request with M-of-N Quorum threshold calculation.
   */
  async createEditRequest({ id, documentId, requesterId, proposedContent, sensitivityTier, poolMemberIds }) {
    if (!documentId || !requesterId || !proposedContent || !sensitivityTier || !Array.isArray(poolMemberIds)) {
      throw this._createError('Missing required fields for edit request creation', 400, 'INVALID_INPUT');
    }

    // Verify Document exists
    const doc = await this.db.getDocument(documentId);
    if (!doc) {
      throw this._createError(`Document with ID '${documentId}' not found`, 404, 'DOCUMENT_NOT_FOUND');
    }

    // Determine Quorum thresholds M-of-N based on Sensitivity Tier
    const tierConfig = getTierConfig(sensitivityTier);
    let requiredM = tierConfig.threshold_m;
    let requiredN = tierConfig.pool_size_n;

    // Dynamically adapt N and M if active system approver pool is smaller (e.g. 3-user deployment)
    if (poolMemberIds.length > 0 && poolMemberIds.length < requiredN) {
      requiredN = poolMemberIds.length;
      requiredM = Math.min(requiredM, requiredN);
    }

    // Validate Pool Member Count matches N requirement
    if (poolMemberIds.length !== requiredN) {
      throw this._createError(
        `Sensitivity tier '${tierConfig.tier}' requires exactly ${requiredN} pool member(s), but ${poolMemberIds.length} provided.`,
        400,
        'POOL_SIZE_MISMATCH'
      );
    }

    // STRICT SECURITY CONSTRAINT: Requester cannot be in the designated approval pool
    if (poolMemberIds.includes(requesterId)) {
      throw this._createError(
        `Self-approval violation: Requester ID '${requesterId}' cannot be included in the approval pool.`,
        400,
        'REQUESTER_IN_APPROVAL_POOL'
      );
    }

    const requestId = id || `req_${crypto.randomBytes(8).toString('hex')}`;

    // Generate anonymous pseudonyms for each approver in the pool
    const pseudonymsMap = {};
    poolMemberIds.forEach((approverId) => {
      pseudonymsMap[approverId] = AnonymityService.generatePseudonym(requestId, approverId);
    });

    const editReqData = {
      id: requestId,
      document_id: documentId,
      requester_id: requesterId,
      proposed_content: proposedContent,
      sensitivity_tier: tierConfig.tier,
      threshold_m: requiredM,
      pool_size_n: requiredN
    };

    const editReq = await this.db.createEditRequest(editReqData, poolMemberIds, pseudonymsMap);
    const poolMembers = await this.db.getPoolMembers(requestId);

    // Audit Log Creation Event
    await this.auditService.logEvent('EDIT_REQUEST_CREATED', requestId, documentId, requesterId, {
      sensitivity_tier: tierConfig.tier,
      threshold_m: requiredM,
      pool_size_n: requiredN,
      pool_pseudonyms: poolMembers.map((m) => m.pseudonym)
    });

    return AnonymityService.sanitizeForPublic(editReq, poolMembers, []);
  }

  /**
   * Casts a vote on an active Edit Request with strict security, self-approval blocking, and quorum state evaluation.
   */
  async castVote({ requestId, voterId, voteChoice }) {
    if (!requestId || !voterId || !['APPROVE', 'REJECT'].includes(voteChoice)) {
      throw this._createError('Invalid voting parameters. Vote choice must be APPROVE or REJECT.', 400, 'INVALID_INPUT');
    }

    const editReq = await this.db.getEditRequest(requestId);
    if (!editReq) {
      throw this._createError(`Edit request '${requestId}' not found`, 404, 'REQUEST_NOT_FOUND');
    }

    if (editReq.status !== 'PENDING') {
      throw this._createError(`Cannot vote on edit request in '${editReq.status}' status.`, 400, 'REQUEST_CLOSED');
    }

    // STRICT SECURITY CONSTRAINT: HARD BACKEND BLOCK FOR SELF-APPROVAL
    if (editReq.requester_id === voterId) {
      throw this._createError(
        `403 Forbidden: Requester '${voterId}' is strictly prohibited from voting on their own edit request.`,
        403,
        'SELF_APPROVAL_FORBIDDEN'
      );
    }

    // Check if voter is in approval pool
    const isMember = await this.db.isPoolMember(requestId, voterId);
    if (!isMember) {
      throw this._createError(
        `User '${voterId}' is not an authorized approver for request '${requestId}'.`,
        403,
        'UNAUTHORIZED_APPROVER'
      );
    }

    // Generate pseudonym for voter
    const voterPseudonym = AnonymityService.generatePseudonym(requestId, voterId);
    const voteId = `vote_${crypto.randomBytes(8).toString('hex')}`;

    // Record Vote (MemoryDb enforces duplicate vote check and throws DUPLICATE_VOTE)
    let vote;
    try {
      vote = await this.db.addVote({
        id: voteId,
        request_id: requestId,
        voter_user_id: voterId,
        voter_pseudonym: voterPseudonym,
        vote_choice: voteChoice
      });
    } catch (err) {
      if (err.code === 'DUPLICATE_VOTE') {
        throw this._createError(
          `User '${voterId}' has already cast a vote on request '${requestId}'.`,
          409,
          'DUPLICATE_VOTE'
        );
      }
      throw err;
    }

    // Fetch updated votes list
    const votes = await this.db.getVotes(requestId);
    const poolMembers = await this.db.getPoolMembers(requestId);

    const approveVotes = votes.filter((v) => v.vote_choice === 'APPROVE');
    const rejectVotes = votes.filter((v) => v.vote_choice === 'REJECT');

    let updatedReq = editReq;
    let versionCreated = null;

    // QUORUM EVALUATION & STATE PROMOTION
    if (approveVotes.length >= editReq.threshold_m) {
      // 1. Mark status APPROVED
      updatedReq = await this.db.updateEditRequestStatus(requestId, 'APPROVED');

      // 2. Fetch original document & bump version
      const doc = await this.db.getDocument(editReq.document_id);
      const newVersionNum = this._bumpVersion(doc.current_version);

      // 3. Create Version Record & update document
      versionCreated = await this.db.createDocumentVersion({
        id: `ver_${crypto.randomBytes(8).toString('hex')}`,
        document_id: doc.id,
        version_number: newVersionNum,
        content: editReq.proposed_content,
        approved_by_request_id: requestId
      });

      await this.db.updateDocumentVersion(doc.id, newVersionNum, editReq.proposed_content);

      // 4. Log to Append-Only WORM Audit Log
      await this.auditService.logEvent('REQUEST_APPROVED', requestId, doc.id, editReq.requester_id, {
        threshold_m: editReq.threshold_m,
        pool_size_n: editReq.pool_size_n,
        approve_count: approveVotes.length,
        reject_count: rejectVotes.length,
        new_version: newVersionNum,
        voter_pseudonym: voterPseudonym
      });

    } else if (poolMembers.length - rejectVotes.length < editReq.threshold_m) {
      // Quorum is mathematically impossible -> REJECTED
      updatedReq = await this.db.updateEditRequestStatus(requestId, 'REJECTED');

      await this.auditService.logEvent('REQUEST_REJECTED', requestId, editReq.document_id, editReq.requester_id, {
        threshold_m: editReq.threshold_m,
        pool_size_n: editReq.pool_size_n,
        approve_count: approveVotes.length,
        reject_count: rejectVotes.length,
        reason: 'Quorum impossible due to reject votes',
        voter_pseudonym: voterPseudonym
      });
    } else {
      // Still PENDING
      await this.auditService.logEvent('VOTE_CAST', requestId, editReq.document_id, editReq.requester_id, {
        vote_choice: voteChoice,
        voter_pseudonym: voterPseudonym,
        approve_count: approveVotes.length,
        threshold_m: editReq.threshold_m
      });
    }

    const sanitized = AnonymityService.sanitizeForPublic(updatedReq, poolMembers, votes);
    return {
      request: sanitized,
      new_version: versionCreated
    };
  }

  /**
   * Retrieves sanitized details for an edit request.
   */
  async getEditRequestDetails(requestId) {
    const editReq = await this.db.getEditRequest(requestId);
    if (!editReq) {
      throw this._createError(`Edit request '${requestId}' not found`, 404, 'REQUEST_NOT_FOUND');
    }
    const poolMembers = await this.db.getPoolMembers(requestId);
    const votes = await this.db.getVotes(requestId);

    return AnonymityService.sanitizeForPublic(editReq, poolMembers, votes);
  }
}

module.exports = ApprovalService;
