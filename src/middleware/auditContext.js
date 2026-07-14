/**
 * Sets PostgreSQL session variables so the trigger can identify
 * the current user even for direct database writes.
 *
 * Usage: call setAuditContext(client, req.user) before any write query.
 */
async function setAuditContext(client, user) {
  await client.query(
    `SELECT
       set_config('app.current_user_id',    $1, true),
       set_config('app.current_user_email', $2, true),
       set_config('app.current_user_role',  $3, true)`,
    [user.userId, user.email, user.role]
  );
}

module.exports = { setAuditContext };
