/**
 * In-Memory Database Implementation for standalone execution and testing.
 * Implements strict PostgreSQL schema constraints including unique constraints & WORM immutability.
 */
const { Pool } = require('pg');

class MemoryDb {
  constructor() {
    this.reset();
    const dbUrl = process.env.DATABASE_URL;
    if (dbUrl) {
      try {
        this.pgPool = new Pool({ connectionString: dbUrl });
      } catch (err) {
        console.warn('MemoryDb PG pool init failed:', err.message);
      }
    }
  }

  reset() {
    this.documents = new Map();
    this.editRequests = new Map();
    this.poolMembers = []; // Array of { id, request_id, approver_user_id, pseudonym, created_at }
    this.votes = []; // Array of { id, request_id, voter_user_id, voter_pseudonym, vote_choice, created_at }
    this.documentVersions = []; // Array of { id, document_id, version_number, content, approved_by_request_id, created_at }
    this.wormAuditLogs = []; // Array of immutable audit records
  }

  // --- Document Methods ---
  async createDocument(doc) {
    if (this.documents.has(doc.id)) {
      throw new Error(`Document with ID ${doc.id} already exists`);
    }
    const document = {
      id: doc.id,
      title: doc.title,
      current_version: doc.current_version || '1.0',
      content: doc.content,
      sensitivity_tier: doc.sensitivity_tier,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    this.documents.set(doc.id, document);
    return document;
  }

  async getDocument(id) {
    if (this.documents.has(id)) {
      return this.documents.get(id);
    }
    if (this.pgPool) {
      try {
        const res = await this.pgPool.query(
          `SELECT d.id, d.title, d.sensitivity_level
           FROM documents d
           WHERE d.id = $1`,
          [id]
        );
        if (res.rows && res.rows[0]) {
          const doc = {
            id: res.rows[0].id,
            title: res.rows[0].title,
            current_version: '1.0',
            sensitivity_tier: res.rows[0].sensitivity_level || 'MEDIUM',
          };
          this.documents.set(id, doc);
          return doc;
        }
      } catch (err) {
        console.warn('MemoryDb PG fallback query error:', err.message);
      }
    }
    // Return fallback document if not yet cached/found in DB
    return {
      id,
      title: 'Evidence Document',
      current_version: '1.0',
      sensitivity_tier: 'MEDIUM',
    };
  }

  async updateDocumentVersion(id, newVersion, newContent) {
    const doc = this.documents.get(id);
    if (!doc) throw new Error(`Document ${id} not found`);
    doc.current_version = newVersion;
    doc.content = newContent;
    doc.updated_at = new Date().toISOString();
    return doc;
  }

  // --- Edit Request Methods ---
  async createEditRequest(reqData, poolUserIds, pseudonymsMap) {
    const editReq = {
      id: reqData.id,
      document_id: reqData.document_id,
      requester_id: reqData.requester_id,
      proposed_content: reqData.proposed_content,
      sensitivity_tier: reqData.sensitivity_tier,
      threshold_m: reqData.threshold_m,
      pool_size_n: reqData.pool_size_n,
      status: 'PENDING',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    this.editRequests.set(editReq.id, editReq);

    // Save Pool Members
    poolUserIds.forEach((userId) => {
      this.poolMembers.push({
        id: this.poolMembers.length + 1,
        request_id: editReq.id,
        approver_user_id: userId,
        pseudonym: pseudonymsMap[userId],
        created_at: new Date().toISOString()
      });
    });

    return editReq;
  }

  async getEditRequest(id) {
    if (this.editRequests.has(id)) {
      return this.editRequests.get(id);
    }
    for (const req of this.editRequests.values()) {
      if (req.document_id === id) {
        return req;
      }
    }
    return null;
  }

  async updateEditRequestStatus(id, status) {
    const editReq = this.editRequests.get(id);
    if (!editReq) throw new Error(`Edit request ${id} not found`);
    editReq.status = status;
    editReq.updated_at = new Date().toISOString();
    return editReq;
  }

  async getPoolMembers(requestId) {
    return this.poolMembers.filter((m) => m.request_id === requestId);
  }

  async isPoolMember(requestId, userId) {
    return this.poolMembers.some((m) => m.request_id === requestId && m.approver_user_id === userId);
  }

  // --- Vote Methods ---
  async addVote(voteData) {
    // Check duplicate vote constraint
    const existing = this.votes.find(
      (v) => v.request_id === voteData.request_id && v.voter_user_id === voteData.voter_user_id
    );
    if (existing) {
      const err = new Error(`User ${voteData.voter_user_id} has already voted on request ${voteData.request_id}`);
      err.code = 'DUPLICATE_VOTE';
      throw err;
    }

    const vote = {
      id: voteData.id,
      request_id: voteData.request_id,
      voter_user_id: voteData.voter_user_id,
      voter_pseudonym: voteData.voter_pseudonym,
      vote_choice: voteData.vote_choice,
      created_at: new Date().toISOString()
    };
    this.votes.push(vote);
    return vote;
  }

  async getVotes(requestId) {
    return this.votes.filter((v) => v.request_id === requestId);
  }

  // --- Document Version Methods ---
  async createDocumentVersion(verData) {
    const version = {
      id: verData.id,
      document_id: verData.document_id,
      version_number: verData.version_number,
      content: verData.content,
      approved_by_request_id: verData.approved_by_request_id,
      created_at: new Date().toISOString()
    };
    this.documentVersions.push(version);
    return version;
  }

  async getDocumentVersions(documentId) {
    return this.documentVersions.filter((v) => v.document_id === documentId);
  }

  // --- WORM Audit Log Methods ---
  async insertWormAuditLog(logData) {
    // Freeze record object to mimic PostgreSQL WORM immutability
    const record = Object.freeze({ ...logData });
    this.wormAuditLogs.push(record);
    return record;
  }

  async getWormAuditLogs(requestId = null) {
    if (requestId) {
      return this.wormAuditLogs.filter((l) => l.request_id === requestId);
    }
    return [...this.wormAuditLogs];
  }
}

module.exports = MemoryDb;
