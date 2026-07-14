/**
 * Archive audit logs older than 12 months to Azure Blob Storage.
 * Run monthly via cron job.
 *
 * Usage: node scripts/archiveLogs.js
 */
require('dotenv').config();
const { pool } = require('../db');
const { BlobServiceClient } = require('@azure/storage-blob');

async function archiveLogs() {
  const cutoff = new Date();
  cutoff.setMonth(cutoff.getMonth() - 12);

  console.log(`Archiving audit logs older than ${cutoff.toISOString()}...`);

  const result = await pool.query(
    `SELECT * FROM audit_logs WHERE created_at < $1 ORDER BY sequence_num ASC`,
    [cutoff]
  );

  if (result.rows.length === 0) {
    console.log('Nothing to archive.');
    await pool.end();
    return;
  }

  console.log(`Found ${result.rows.length} records to archive.`);

  // Upload to Azure Blob Storage as newline-delimited JSON
  const blobServiceClient = BlobServiceClient.fromConnectionString(
    process.env.AZURE_STORAGE_CONNECTION_STRING
  );
  const containerClient = blobServiceClient.getContainerClient('audit-archive');
  await containerClient.createIfNotExists();

  const blobName        = `audit-${cutoff.toISOString().slice(0, 7)}.ndjson`;
  const blockBlobClient = containerClient.getBlockBlobClient(blobName);

  const content = result.rows.map(r => JSON.stringify(r)).join('\n');
  await blockBlobClient.upload(content, Buffer.byteLength(content), {
    blobHTTPHeaders: { blobContentType: 'application/x-ndjson' },
  });
  console.log(`Uploaded ${blobName} to Azure Blob Storage.`);

  // Move to archive table
  await pool.query(
    `INSERT INTO audit_logs_archive SELECT * FROM audit_logs WHERE created_at < $1 ON CONFLICT DO NOTHING`,
    [cutoff]
  );

  // Remove from primary table
  const deleted = await pool.query(
    `DELETE FROM audit_logs WHERE created_at < $1`,
    [cutoff]
  );
  console.log(`Moved ${deleted.rowCount} records to audit_logs_archive.`);
  console.log('Archive complete.');

  await pool.end();
}

archiveLogs().catch((err) => {
  console.error('Archive failed:', err.message);
  process.exit(1);
});
