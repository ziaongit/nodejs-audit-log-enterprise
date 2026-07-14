const express = require('express');
const jwt     = require('jsonwebtoken');
const { pool } = require('../../db');
const audit    = require('../services/auditService');

const router = express.Router();

// Simple auth middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// GET /api/records
router.get('/', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT * FROM records ORDER BY created_at DESC LIMIT 50');

  audit.log({
    userId:    req.user.userId || req.user.sub,
    userEmail: req.user.email,
    userRole:  req.user.role || 'user',
    action:    'VIEW',
    resource:  'records',
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
  });

  res.json(result.rows);
});

// POST /api/records
router.post('/', authMiddleware, async (req, res) => {
  const { name, data } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  const result = await pool.query(
    'INSERT INTO records (name, data) VALUES ($1, $2) RETURNING *',
    [name, data ? JSON.stringify(data) : null]
  );
  const record = result.rows[0];

  audit.log({
    userId:     req.user.userId || req.user.sub,
    userEmail:  req.user.email,
    userRole:   req.user.role || 'user',
    action:     'CREATE',
    resource:   'records',
    resourceId: record.id,
    newValues:  record,
    ipAddress:  req.ip,
    userAgent:  req.headers['user-agent'],
  });

  res.status(201).json(record);
});

// PUT /api/records/:id
router.put('/:id', authMiddleware, async (req, res) => {
  const oldResult = await pool.query('SELECT * FROM records WHERE id = $1', [req.params.id]);
  if (!oldResult.rows[0]) return res.status(404).json({ error: 'Not found' });

  const updated = await pool.query(
    'UPDATE records SET name = COALESCE($1, name), data = COALESCE($2, data), updated_at = NOW() WHERE id = $3 RETURNING *',
    [req.body.name, req.body.data ? JSON.stringify(req.body.data) : null, req.params.id]
  );

  audit.log({
    userId:     req.user.userId || req.user.sub,
    userEmail:  req.user.email,
    userRole:   req.user.role || 'user',
    action:     'UPDATE',
    resource:   'records',
    resourceId: req.params.id,
    oldValues:  oldResult.rows[0],
    newValues:  updated.rows[0],
    reason:     req.body.reason || null,
    ipAddress:  req.ip,
    userAgent:  req.headers['user-agent'],
  });

  res.json(updated.rows[0]);
});

// DELETE /api/records/:id
router.delete('/:id', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT * FROM records WHERE id = $1', [req.params.id]);
  if (!result.rows[0]) return res.status(404).json({ error: 'Not found' });

  await pool.query('DELETE FROM records WHERE id = $1', [req.params.id]);

  audit.log({
    userId:     req.user.userId || req.user.sub,
    userEmail:  req.user.email,
    userRole:   req.user.role || 'user',
    action:     'DELETE',
    resource:   'records',
    resourceId: req.params.id,
    oldValues:  result.rows[0],
    reason:     req.body.reason || null,
    ipAddress:  req.ip,
    userAgent:  req.headers['user-agent'],
  });

  res.json({ deleted: true });
});

// GET /api/records/audit — query audit logs
router.get('/audit', authMiddleware, async (req, res) => {
  const { userId, resource, action, source, from, to, limit = 100 } = req.query;

  let query = 'SELECT * FROM audit_logs WHERE 1=1';
  const params = [];

  if (userId)   { params.push(userId);   query += ` AND user_id = $${params.length}`; }
  if (resource) { params.push(resource); query += ` AND resource = $${params.length}`; }
  if (action)   { params.push(action);   query += ` AND action = $${params.length}`; }
  if (source)   { params.push(source);   query += ` AND source = $${params.length}`; }
  if (from)     { params.push(from);     query += ` AND created_at >= $${params.length}`; }
  if (to)       { params.push(to);       query += ` AND created_at <= $${params.length}`; }

  params.push(Math.min(parseInt(limit), 500));
  query += ` ORDER BY sequence_num DESC LIMIT $${params.length}`;

  const result = await pool.query(query, params);
  res.json(result.rows);
});

module.exports = router;
