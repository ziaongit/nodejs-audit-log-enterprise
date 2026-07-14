const crypto = require('crypto');

/**
 * Compute SHA-256 hash for an audit log row.
 * Each row's hash depends on its content AND the previous row's hash.
 * This creates a chain — modifying any historical record breaks all subsequent hashes.
 */
function computeRowHash({
  prevHash, userId, userEmail, userRole,
  action, resource, resourceId, oldValues, newValues, createdAt,
}) {
  const payload = JSON.stringify({
    prevHash:   prevHash || 'GENESIS',
    userId,
    userEmail,
    userRole,
    action,
    resource,
    resourceId:  resourceId  || null,
    oldValues:   oldValues   || null,
    newValues:   newValues   || null,
    createdAt:   createdAt instanceof Date
                   ? createdAt.toISOString()
                   : new Date(createdAt).toISOString(),
  });

  return crypto.createHash('sha256').update(payload).digest('hex');
}

module.exports = { computeRowHash };
