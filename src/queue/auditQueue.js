const { Queue, Worker } = require('bullmq');
const Redis             = require('ioredis');
const { writeAuditLog } = require('../services/auditService');

const connection = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: null,
});

// Queue: accepts audit events from the application (non-blocking)
const auditQueue = new Queue('audit-logs', { connection });

// Worker: processes one event at a time (concurrency=1 maintains chain order)
const auditWorker = new Worker(
  'audit-logs',
  async (job) => {
    await writeAuditLog(job.data);
  },
  {
    connection,
    concurrency: 1,     // MUST be 1 — hash chain requires sequential writes
    limiter: {
      max: 500,
      duration: 1000,   // Max 500 audit writes per second
    },
  }
);

auditWorker.on('completed', (job) => {
  console.log(`[AuditWorker] Job ${job.id} completed`);
});

auditWorker.on('failed', (job, err) => {
  console.error(`[AuditWorker] Job ${job?.id} failed:`, err.message);
  // Production: send to dead-letter queue + trigger alert
});

/**
 * Queue-based log function (use for high-volume applications).
 * Non-blocking — pushes to Redis queue and returns immediately.
 */
async function logQueued(data) {
  await auditQueue.add('log', data, {
    attempts: 3,
    backoff: { type: 'exponential', delay: 1000 },
    removeOnComplete: 100,
    removeOnFail:     500,
  });
}

module.exports = { logQueued, auditQueue, auditWorker };
