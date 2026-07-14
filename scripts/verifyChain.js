/**
 * Verify audit log chain integrity and alert on tampering.
 * Run after an incident or on a nightly schedule.
 *
 * Usage: node scripts/verifyChain.js
 * Cron:  0 2 * * * node /app/scripts/verifyChain.js >> /var/log/audit-verify.log 2>&1
 */
require('dotenv').config();
const { pool }           = require('../db');
const { computeRowHash } = require('../src/utils/hashChain');

async function verifyChain() {
  console.log('Starting audit log chain verification...');
  console.log('-------------------------------------------');

  const result = await pool.query(
    `SELECT * FROM audit_logs ORDER BY sequence_num ASC`
  );

  const rows              = result.rows;
  let prevHash            = null;
  let broken              = 0;
  let firstBrokenSequence = null;

  for (const row of rows) {
    const expectedHash = computeRowHash({
      prevHash:   prevHash || null,
      userId:     row.user_id,
      userEmail:  row.user_email,
      userRole:   row.user_role,
      action:     row.action,
      resource:   row.resource,
      resourceId: row.resource_id,
      oldValues:  row.old_values,
      newValues:  row.new_values,
      createdAt:  new Date(row.created_at),
    });

    if (row.row_hash !== expectedHash) {
      console.error(`CHAIN BROKEN at sequence_num=${row.sequence_num} (id=${row.id})`);
      console.error(`  Expected hash: ${expectedHash}`);
      console.error(`  Stored hash:   ${row.row_hash}`);
      if (!firstBrokenSequence) firstBrokenSequence = row.sequence_num;
      broken++;
    }

    prevHash = row.row_hash;
  }

  console.log('-------------------------------------------');

  if (broken === 0) {
    console.log(`Chain intact. ${rows.length} records verified.`);
    process.exit(0);
  } else {
    console.error(`${broken} broken link(s) detected. Investigate immediately.`);
    await notifySecurityTeam({ broken, firstBrokenSequence, total: rows.length });
    process.exit(1);
  }
}

/**
 * Send a critical alert when chain tampering is detected.
 * Supports any webhook-based alert system: PagerDuty, Slack, Teams, Opsgenie.
 * Set ALERT_WEBHOOK_URL in your environment.
 */
async function notifySecurityTeam({ broken, firstBrokenSequence, total }) {
  const message = {
    severity:            'CRITICAL',
    title:               'Audit Log Integrity Violation Detected',
    brokenLinks:         broken,
    firstBrokenSequence: firstBrokenSequence,
    totalRecordsChecked: total,
    timestamp:           new Date().toISOString(),
    action:              'Immediate investigation required. Do not delete or modify any database records.',
  };

  console.error('[SECURITY ALERT]', JSON.stringify(message, null, 2));

  if (process.env.ALERT_WEBHOOK_URL) {
    try {
      // node-fetch v3 is ESM; use dynamic import for CommonJS compatibility
      const { default: fetch } = await import('node-fetch');
      await fetch(process.env.ALERT_WEBHOOK_URL, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(message),
      });
      console.log('Security team notified via webhook.');
    } catch (err) {
      console.error('Failed to send alert webhook:', err.message);
    }
  }
}

verifyChain()
  .catch((err) => {
    console.error('Verification failed:', err.message);
    process.exit(1);
  })
  .finally(() => pool.end());
