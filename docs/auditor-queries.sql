-- ============================================================
--  Auditor Query Reference — nodejs-audit-log-enterprise
--  Keep this file ready. When the SOC 2 auditor asks, run
--  the relevant query and export to CSV.
-- ============================================================

-- 1. All actions by a specific user in the last 30 days
SELECT action, resource, resource_id, old_values, new_values,
       created_at, ip_address, reason
FROM audit_logs
WHERE user_email = 'john.doe@company.com'
  AND created_at >= NOW() - INTERVAL '30 days'
ORDER BY created_at DESC;


-- 2. Full change history for a specific record
SELECT user_email, user_role, action, reason,
       old_values, new_values, created_at, ip_address, source
FROM audit_logs
WHERE resource = 'records'
  AND resource_id = 'abc-123-def-456'
ORDER BY created_at DESC;


-- 3. All direct database changes (bypassed the application)
--    First query a security auditor runs after an incident.
SELECT user_email, action, resource, resource_id, created_at
FROM audit_logs
WHERE source = 'trigger'
ORDER BY created_at DESC;


-- 4. Prove audit log permissions (run in psql, share output)
--    Shows app_user has no UPDATE/DELETE/TRUNCATE rights.
\dp audit_logs


-- 5. All bulk deletes in the last quarter
SELECT user_email, resource,
       COUNT(*)         AS records_deleted,
       MIN(created_at)  AS started_at,
       MAX(created_at)  AS finished_at
FROM audit_logs
WHERE action = 'DELETE'
  AND created_at >= NOW() - INTERVAL '90 days'
GROUP BY user_email, resource
ORDER BY records_deleted DESC;


-- 6. Who accessed the audit log admin endpoint
SELECT user_email, created_at, ip_address
FROM audit_logs
WHERE resource = 'audit_logs' AND action = 'VIEW'
ORDER BY created_at DESC;


-- 7. All actions during a specific incident window
SELECT *
FROM audit_logs
WHERE created_at BETWEEN '2025-03-10 14:00:00+00' AND '2025-03-10 16:00:00+00'
ORDER BY sequence_num ASC;


-- 8. Sequence number gaps (indicates deleted rows despite REVOKE)
SELECT a.sequence_num + 1 AS missing_sequence
FROM audit_logs a
LEFT JOIN audit_logs b ON b.sequence_num = a.sequence_num + 1
WHERE b.sequence_num IS NULL
  AND a.sequence_num < (SELECT MAX(sequence_num) FROM audit_logs)
ORDER BY missing_sequence;


-- 9. Users with the most high-risk actions (DELETE/UPDATE) this month
SELECT user_email, user_role, action, COUNT(*) AS total
FROM audit_logs
WHERE action IN ('DELETE', 'UPDATE')
  AND created_at >= DATE_TRUNC('month', NOW())
GROUP BY user_email, user_role, action
ORDER BY total DESC;


-- 10. Retention check — confirm logs older than 12 months are in archive
SELECT MIN(created_at) AS oldest_live_record FROM audit_logs;
SELECT MIN(created_at) AS oldest_archived_record FROM audit_logs_archive;
