const express = require('express');
require('dotenv').config();
// Use PostgresDb in production; tests can still pass a customDb (MemoryDb)
const PostgresDb = require('./db/postgresDb');
const MemoryDb = require('./db/memoryDb');
const ApprovalService = require('./services/approvalService');
const AuditService = require('./services/auditService');
const ApprovalController = require('./controllers/approvalController');
const createApprovalRoutes = require('./routes/approvalRoutes');

function createApp(customDb = null) {
  const app = express();
  app.use(express.json());

  // Use MemoryDb with PG-backed document lookup
  const db = customDb || new MemoryDb();
  const approvalService = new ApprovalService(db);
  const auditService = new AuditService(db);
  const approvalController = new ApprovalController(approvalService, auditService, db);

  // Mount API routes
  app.use('/api/approval', createApprovalRoutes(approvalController));

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP', module: 'SecureChain DMS M-of-N Approval Engine' });
  });

  // Centralized Error Handling Middleware
  app.use((err, req, res, next) => {
    const statusCode = err.statusCode || 500;
    res.status(statusCode).json({
      error: true,
      code: err.code || 'INTERNAL_SERVER_ERROR',
      message: err.message
    });
  });

  return { app, db, approvalService, auditService };
}

module.exports = createApp;
