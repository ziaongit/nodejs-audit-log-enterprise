/**
 * Audit Log Test Suite
 *
 * Verifies:
 * - old_values are captured BEFORE the write
 * - Identity is always read from JWT, never from request body
 * - Hash chain remains intact after sequential writes
 * - Tampered records are detected during verification
 *
 * Run with: npm test
 * Note: --runInBand (serial execution) is required — hash chain writes must be sequential.
 */

require('dotenv').config({ path: '.env.test' });
const request = require('supertest');
const app     = require('../app');
const { pool } = require('../db');
const { computeRowHash } = require('../src/utils/hashChain');
const jwt = require('jsonwebtoken');

// Generate a test admin token
const adminToken = jwt.sign(
  { userId: '00000000-0000-0000-0000-000000000001', email: 'admin@test.com', role: 'Admin' },
  process.env.JWT_SECRET || 'test-secret'
);

beforeAll(async () => {
  // Clear test data from previous runs
  await pool.query('DELETE FROM audit_logs');
});

afterAll(async () => {
  await pool.query('DELETE FROM audit_logs');
  await pool.end();
});

// Helper: wait for async BullMQ worker to flush
const waitForQueue = (ms = 400) => new Promise(resolve => setTimeout(resolve, ms));

// ─── Test Group 1: old_values capture ────────────────────────────────────────

describe('Audit Log — old_values capture', () => {
  it('captures old_values BEFORE the update, not after', async () => {
    const create = await request(app)
      .post('/api/records')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'original-name', data: { key: 'original-value' } });

    expect(create.status).toBe(201);
    const recordId = create.body.id;

    await request(app)
      .put(`/api/records/${recordId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'updated-name', data: { key: 'new-value' } });

    await waitForQueue();

    const result = await pool.query(
      `SELECT * FROM audit_logs WHERE resource_id = $1 AND action = 'UPDATE'`,
      [recordId]
    );

    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].old_values.name).toBe('original-name');
    expect(result.rows[0].new_values.name).toBe('updated-name');
  });
});

// ─── Test Group 2: Identity integrity ────────────────────────────────────────

describe('Audit Log — identity integrity', () => {
  it('logs identity from the JWT, ignoring any userId in the request body', async () => {
    await request(app)
      .post('/api/records')
      .set('Authorization', `Bearer ${adminToken}`)
      // Attacker tries to inject a different identity via the request body
      .send({ name: 'identity-test', userId: 'attacker-uuid', userEmail: 'attacker@evil.com' });

    await waitForQueue();

    const result = await pool.query(
      `SELECT user_email FROM audit_logs WHERE action = 'CREATE' ORDER BY created_at DESC LIMIT 1`
    );

    // Must reflect the JWT identity, not the attacker-provided values
    expect(result.rows[0].user_email).toBe('admin@test.com');
  });
});

// ─── Test Group 3: Hash chain integrity ──────────────────────────────────────

describe('Audit Log — hash chain integrity', () => {
  it('chain is intact after 10 sequential writes', async () => {
    for (let i = 0; i < 10; i++) {
      await request(app)
        .post('/api/records')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ name: `Chain record ${i}` });
    }

    // Wait for all 10 events to be processed by the worker
    await waitForQueue(1500);

    const rows = (await pool.query(
      `SELECT * FROM audit_logs ORDER BY sequence_num ASC`
    )).rows;

    let prevHash = null;
    let broken   = 0;

    for (const row of rows) {
      const expected = computeRowHash({
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

      if (row.row_hash !== expected) broken++;
      prevHash = row.row_hash;
    }

    expect(broken).toBe(0);
  });

  it('detects a tampered record', async () => {
    const last = await pool.query(
      `SELECT id FROM audit_logs ORDER BY sequence_num DESC LIMIT 1`
    );

    // Simulate tampering (bypasses REVOKE — test DB user has superuser rights)
    await pool.query(
      `UPDATE audit_logs SET new_values = '{"tampered": true}'::jsonb WHERE id = $1`,
      [last.rows[0].id]
    );

    const rows = (await pool.query(
      `SELECT * FROM audit_logs ORDER BY sequence_num ASC`
    )).rows;

    let prevHash = null;
    let broken   = 0;

    for (const row of rows) {
      const expected = computeRowHash({
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

      if (row.row_hash !== expected) broken++;
      prevHash = row.row_hash;
    }

    expect(broken).toBeGreaterThan(0);
  });
});
