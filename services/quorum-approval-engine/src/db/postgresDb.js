/**
 * postgresDb.js
 * Drop-in replacement for memoryDb.js that uses real PostgreSQL.
 * Implements the exact same interface so approvalService.js needs ZERO changes.
 */
const { Pool } = require('pg');

class PostgresDb {
  constructor() {
    this.pool = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgresql://postgres.mkgjjgrgwodcctyagkrt:Shreyash%401234@aws-0-ap-northeast-1.pooler.supabase.com:5432/postgres',
    });
  }

  // --- Documents ---
  async getDocument(documentId) {
    const res = await this.pool.query(
      `SELECT d.id, d.title, dv.version_number AS current_version, d.sensitivity_level
       FROM documents d
       LEFT JOIN document_versions dv ON dv.id = d.current_version_id
       WHERE d.id = $1`,
      [documentId]
    );
    return res.rows[0] || null;
  }

  async updateDocumentVersion(documentId, newVersion, content) {
    // Version bumping is handled by the Python gateway; this is a no-op stub
    return { document_id: documentId, current_version: newVersion };
  }

  async createDocumentVersion(data) {
    const res = await this.pool.query(
      `INSERT INTO document_versions
         (id, document_id, version_number, original_filename, created_by, status)
       VALUES ($1, $2, $3, $4, $5, 'LOCKED')
       RETURNING *`,
      [data.id, data.document_id, data.version_number, data.content?.slice(0, 200) || '', data.approved_by_request_id]
    );
    return res.rows[0];
  }

  // --- Edit Requests ---
  async createEditRequest(editReqData, poolMemberIds, pseudonymsMap) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      // UPSERT: If a request with this id already exists (e.g. stale/broken),
      // reset it to PENDING and update its content.
      const res = await client.query(
        `INSERT INTO edit_requests
           (id, document_id, requester_id, proposed_content_summary,
            sensitivity_level, status)
         VALUES ($1, $2, $3, $4, $5, 'PENDING')
         ON CONFLICT (id) DO UPDATE SET
           status = 'PENDING',
           proposed_content_summary = EXCLUDED.proposed_content_summary,
           sensitivity_level = EXCLUDED.sensitivity_level
         RETURNING *`,
        [editReqData.id, editReqData.document_id, editReqData.requester_id,
         editReqData.proposed_content?.slice(0, 500) || '',
         editReqData.sensitivity_tier || 'MEDIUM']
      );
      const req = res.rows[0];

      // Remove stale pool assignments first (handles re-registration case)
      await client.query(
        `DELETE FROM approval_assignments WHERE edit_request_id = $1`,
        [editReqData.id]
      );

      // Insert fresh pool members
      for (const approverId of poolMemberIds) {
        await client.query(
          `INSERT INTO approval_assignments
             (edit_request_id, approver_id, pseudonym, status)
           VALUES ($1, $2, $3, 'PENDING')`,
          [editReqData.id, approverId, pseudonymsMap[approverId]]
        );
      }

      await client.query('COMMIT');
      req.threshold_m = editReqData.threshold_m;
      req.pool_size_n = editReqData.pool_size_n;
      req.requester_id = editReqData.requester_id;
      return req;
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }


  async getEditRequest(requestId) {
    const res = await this.pool.query(
      `SELECT er.*,
              qp.required_approvals AS threshold_m,
              qp.pool_size          AS pool_size_n
       FROM edit_requests er
       LEFT JOIN quorum_policies qp ON qp.sensitivity_level = er.sensitivity_level
       WHERE er.id = $1`,
      [requestId]
    );
    const row = res.rows[0];
    if (!row) return null;
    row.threshold_m = row.threshold_m || 1;
    row.pool_size_n = row.pool_size_n || 1;
    return row;
  }

  async updateEditRequestStatus(requestId, newStatus) {
    const res = await this.pool.query(
      `UPDATE edit_requests SET status = $1, updated_at = NOW()
       WHERE id = $2 RETURNING *`,
      [newStatus, requestId]
    );
    return res.rows[0];
  }

  // --- Pool Members ---
  async getPoolMembers(requestId) {
    const res = await this.pool.query(
      `SELECT approver_id AS user_id, pseudonym
       FROM approval_assignments WHERE edit_request_id = $1`,
      [requestId]
    );
    return res.rows;
  }

  async isPoolMember(requestId, userId) {
    const res = await this.pool.query(
      `SELECT 1 FROM approval_assignments
       WHERE edit_request_id = $1 AND approver_id = $2 LIMIT 1`,
      [requestId, userId]
    );
    return res.rows.length > 0;
  }

  // --- Votes ---
  async addVote(voteData) {
    // Check for duplicate
    const dup = await this.pool.query(
      `SELECT 1 FROM approvals WHERE edit_request_id = $1 AND approver_id = $2`,
      [voteData.request_id, voteData.voter_user_id]
    );
    if (dup.rows.length > 0) {
      const err = new Error('Duplicate vote');
      err.code = 'DUPLICATE_VOTE';
      throw err;
    }

    const res = await this.pool.query(
      `INSERT INTO approvals (id, edit_request_id, approver_id, decision, pseudonym)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [voteData.id, voteData.request_id, voteData.voter_user_id,
       voteData.vote_choice, voteData.voter_pseudonym]
    );
    return res.rows[0];
  }

  async getVotes(requestId) {
    const res = await this.pool.query(
      `SELECT id, approver_id AS voter_user_id, decision AS vote_choice,
              pseudonym AS voter_pseudonym
       FROM approvals WHERE edit_request_id = $1`,
      [requestId]
    );
    return res.rows;
  }

  // --- WORM Audit Logs ---
  async insertWormAuditLog(entry) {
    await this.pool.query(
      `INSERT INTO audit_logs (id, event_type, document_id, actor_id, severity, metadata)
       VALUES ($1, $2, $3, $4, 'INFO', $5::jsonb)`,
      [entry.id, entry.event_type, entry.document_id, entry.requester_id,
       JSON.stringify(entry.action_details)]
    );
    return entry;
  }

  async getWormAuditLogs(requestId = null) {
    let res;
    if (requestId) {
      res = await this.pool.query(
        `SELECT * FROM audit_logs WHERE metadata->>'request_id' = $1 ORDER BY created_at DESC`,
        [requestId]
      );
    } else {
      res = await this.pool.query(`SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500`);
    }
    return res.rows;
  }
}

module.exports = PostgresDb;
