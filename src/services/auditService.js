const { pool }           = require('../../db');
const { computeRowHash } = require('../utils/hashChain');

/**
 * Write an audit log entry with hash chaining.
 * Fetches the previous row's hash, computes the new hash, then inserts.
 * Called directly (no queue) — use auditQueue.js for high-volume scenarios.
 */
async function writeAuditLog({
  userId, userEmail, userRole, action, resource,
  resourceId = null, oldValues = null, newValues = null,
  reason = null, ipAddress = null, userAgent = null,
  source = 'app',
}) {
  // Fetch the most recent hash to continue the chain
  const prev = await pool.query(
    `SELECT row_hash FROM audit_logs ORDER BY sequence_num DESC LIMIT 1`
  );
  const prevHash = prev.rows[0]?.row_hash || null;

  const createdAt = new Date();

  const rowHash = computeRowHash({
    prevHash,
    userId, userEmail, userRole,
    action, resource, resourceId,
    oldValues, newValues, createdAt,
  });

  await pool.query(
    `INSERT INTO audit_logs
       (user_id, user_email, user_role, action, resource, resource_id,
        old_values, new_values, reason, ip_address, user_agent,
        source, prev_hash, row_hash, created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
    [
      userId, userEmail, userRole,
      action, resource, resourceId,
      oldValues  ? JSON.stringify(oldValues)  : null,
      newValues  ? JSON.stringify(newValues)  : null,
      reason, ipAddress, userAgent,
      source, prevHash, rowHash, createdAt,
    ]
  );
}

/**
 * Fire-and-forget audit log.
 * Never blocks the request. Errors are caught and logged.
 */
function log(data) {
  writeAuditLog(data).catch((err) => {
    console.error('[AuditService] Failed to write log:', err.message);
  });
}

module.exports = { log, writeAuditLog };
