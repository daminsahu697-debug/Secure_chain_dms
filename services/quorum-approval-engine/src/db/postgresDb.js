/**
 * postgresDb.js
 * Drop-in replacement for memoryDb.js that uses real PostgreSQL.
 * Implements the exact same interface so approvalService.js needs ZERO changes.
 */
const { Pool } = require('pg');

class PostgresDb {
  constructor() {
    this.pool = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgresql://postgres.buvjudpqfzscxoeqwnay:Securechaindms%40123@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres',
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

      // The Python backend already created the edit_requests row with all required fields.
      // Here we ONLY manage the approval_assignments pool.
      // First, remove stale pool assignments (handles re-registration case)
      await client.query(
        `DELETE FROM approval_assignments WHERE edit_request_id = $1`,
        [editReqData.id]
      );

      // Insert fresh pool members using actual schema (no pseudonym column)
      for (const approverId of poolMemberIds) {
        await client.query(
          `INSERT INTO approval_assignments
             (id, edit_request_id, approver_id, anonymous_token, status)
           VALUES (gen_random_uuid(), $1, $2::uuid, gen_random_uuid(), 'PENDING')
           ON CONFLICT DO NOTHING`,
          [editReqData.id, approverId]
        );
      }

      await client.query('COMMIT');

      // Return a synthetic row matching expected shape
      return {
        id: editReqData.id,
        document_id: editReqData.document_id,
        requester_id: editReqData.requester_id,
        status: 'PENDING',
        threshold_m: editReqData.threshold_m,
        pool_size_n: editReqData.pool_size_n,
        sensitivity_level: editReqData.sensitivity_tier || 'MEDIUM',
      };
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }


  async getEditRequest(requestId) {
    // Use actual schema: join via quorum_policy_id, fallback to MEDIUM policy if null
    const res = await this.pool.query(
      `SELECT er.*,
              COALESCE(qp.required_approvals, 2) AS threshold_m,
              COALESCE(qp.pool_size, 3)          AS pool_size_n,
              COALESCE(qp.sensitivity_level, 'MEDIUM') AS sensitivity_level
       FROM edit_requests er
       LEFT JOIN quorum_policies qp ON qp.id = er.quorum_policy_id
       WHERE er.id = $1`,
      [requestId]
    );
    const row = res.rows[0];
    if (!row) return null;
    row.threshold_m = row.threshold_m || 2;
    row.pool_size_n = row.pool_size_n || 3;
    row.sensitivity_level = row.sensitivity_level || 'MEDIUM';
    // Normalize requester_id field name
    row.requester_id = row.requester_id;
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
    // actual schema has no pseudonym column — generate one from approver_id
    const res = await this.pool.query(
      `SELECT approver_id AS user_id,
              CONCAT('Approver-', SUBSTRING(approver_id::text, 1, 8)) AS pseudonym
       FROM approval_assignments WHERE edit_request_id = $1`,
      [requestId]
    );
    return res.rows;
  }

  async isPoolMember(requestId, userId) {
    const res = await this.pool.query(
      `SELECT 1 FROM approval_assignments
       WHERE edit_request_id = $1 AND approver_id = $2::uuid LIMIT 1`,
      [requestId, userId]
    );
    return res.rows.length > 0;
  }

  // --- Votes ---
  async addVote(voteData) {
    // Find the assignment_id for this approver on this request
    const assignRes = await this.pool.query(
      `SELECT id FROM approval_assignments
       WHERE edit_request_id = $1 AND approver_id = $2::uuid LIMIT 1`,
      [voteData.request_id, voteData.voter_user_id]
    );

    // Check for duplicate via approvals table (keyed by assignment_id)
    let assignmentId = assignRes.rows[0]?.id;
    if (assignmentId) {
      const dup = await this.pool.query(
        `SELECT 1 FROM approvals WHERE assignment_id = $1`,
        [assignmentId]
      );
      if (dup.rows.length > 0) {
        const err = new Error('Duplicate vote');
        err.code = 'DUPLICATE_VOTE';
        throw err;
      }
    } else {
      // No assignment yet — create one on the fly
      const newAssign = await this.pool.query(
        `INSERT INTO approval_assignments (id, edit_request_id, approver_id, anonymous_token, status)
         VALUES (gen_random_uuid(), $1, $2::uuid, gen_random_uuid(), 'PENDING')
         RETURNING id`,
        [voteData.request_id, voteData.voter_user_id]
      );
      assignmentId = newAssign.rows[0].id;
    }

    // Insert approval record (actual schema: id, assignment_id, decision, remarks, approved_at)
    const res = await this.pool.query(
      `INSERT INTO approvals (id, assignment_id, decision, remarks, approved_at)
       VALUES (gen_random_uuid(), $1, $2, $3, NOW()) RETURNING *`,
      [assignmentId, voteData.vote_choice, voteData.voter_pseudonym || null]
    );
    // Update assignment status
    await this.pool.query(
      `UPDATE approval_assignments SET status = $1 WHERE id = $2`,
      [voteData.vote_choice, assignmentId]
    );
    return { ...res.rows[0], vote_choice: voteData.vote_choice };
  }

  async getVotes(requestId) {
    // Actual schema: approvals links via assignment_id -> approval_assignments
    const res = await this.pool.query(
      `SELECT ap.id,
              aa.approver_id AS voter_user_id,
              ap.decision AS vote_choice,
              CONCAT('Approver-', SUBSTRING(aa.approver_id::text, 1, 8)) AS voter_pseudonym
       FROM approvals ap
       JOIN approval_assignments aa ON aa.id = ap.assignment_id
       WHERE aa.edit_request_id = $1`,
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
