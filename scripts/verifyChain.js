/**
 * Verify audit log chain integrity.
 * Run after an incident or on a nightly schedule.
 *
 * Usage: node scripts/verifyChain.js
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

  const rows   = result.rows;
  let prevHash = null;
  let broken   = 0;

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
    process.exit(1);
  }
}

verifyChain()
  .catch((err) => {
    console.error('Verification failed:', err.message);
    process.exit(1);
  })
  .finally(() => pool.end());
