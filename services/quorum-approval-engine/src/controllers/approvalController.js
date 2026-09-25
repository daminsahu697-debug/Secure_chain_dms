class ApprovalController {
  constructor(approvalService, auditService, db) {
    this.approvalService = approvalService;
    this.auditService = auditService;
    this.db = db;
  }

  /**
   * Helper to seed/create initial documents for testing/demo
   */
  createDocument = async (req, res, next) => {
    try {
      const { id, title, content, sensitivity_tier } = req.body;
      const doc = await this.db.createDocument({
        id: id || `doc_${Date.now()}`,
        title: title || 'Untitled Security Document',
        content: content || 'Initial document content v1.0',
        sensitivity_tier: sensitivity_tier || 'LOW'
      });
      return res.status(201).json({ success: true, document: doc });
    } catch (err) {
      next(err);
    }
  };

  /**
   * POST /api/approval/requests
   * Creates a new Edit Request
   */
  createRequest = async (req, res, next) => {
    try {
      const { id, documentId, requesterId, proposedContent, sensitivityTier, poolMemberIds } = req.body;

      const result = await this.approvalService.createEditRequest({
        id,
        documentId,
        requesterId,
        proposedContent,
        sensitivityTier,
        poolMemberIds
      });

      return res.status(201).json({
        success: true,
        message: 'Edit request created successfully',
        request: result
      });
    } catch (err) {
      next(err);
    }
  };

  /**
   * POST /api/approval/requests/:id/vote
   * Casts a vote (APPROVE / REJECT) on an Edit Request
   */
  vote = async (req, res, next) => {
    try {
      const requestId = req.params.id;
      const { voterId, voteChoice } = req.body;

      const result = await this.approvalService.castVote({
        requestId,
        voterId,
        voteChoice
      });

      return res.status(200).json({
        success: true,
        message: `Vote '${voteChoice}' recorded successfully`,
        data: result
      });
    } catch (err) {
      next(err);
    }
  };

  /**
   * GET /api/approval/requests/:id
   * Fetches anonymous payload of request
   */
  getRequestDetails = async (req, res, next) => {
    try {
      const requestId = req.params.id;
      const details = await this.approvalService.getEditRequestDetails(requestId);
      return res.status(200).json({ success: true, request: details });
    } catch (err) {
      next(err);
    }
  };

  /**
   * GET /api/approval/audit-logs
   * Fetches WORM audit logs
   */
  getAuditLogs = async (req, res, next) => {
    try {
      const requestId = req.query.requestId;
      const logs = await this.auditService.getAuditLogs(requestId);
      return res.status(200).json({ success: true, logs });
    } catch (err) {
      next(err);
    }
  };
}

module.exports = ApprovalController;
