# Enterprise-Grade Tamper-Proof Audit Log in Node.js and PostgreSQL

Production-ready audit logging with **hash chaining**, **PostgreSQL triggers**, **BullMQ async queue**, and **compliance-ready schema** — no third-party audit service required.

Built as the companion repository for the DevOps.com article:
**[How to Build an Enterprise-Grade Tamper-Proof Audit Log in Node.js and PostgreSQL](https://devops.com/author/zia-ullah/)**

---

## What This Provides

| Feature | Description |
|---------|-------------|
| Database-level protection | REVOKE UPDATE/DELETE/TRUNCATE — even developers can't erase history |
| Hash chaining | SHA-256 chain — tampering any record breaks all subsequent hashes |
| PostgreSQL trigger | Catches direct DB writes that bypass the application |
| Async queue (BullMQ) | Non-blocking logging at scale — chain integrity maintained |
| Chain verification | `npm run verify-chain` — proves integrity after incidents |
| Log archiving | Monthly archive to Azure Blob, never delete |
| Compliance-ready | Maps to SOC 2, GDPR Art. 30, HIPAA 164.312, ISO 27001 |

---

## Architecture

```
HTTP Request
     │
     ▼
Route Handler
  ├── Business Logic ──► PostgreSQL (records table)
  │                           │
  │                     Trigger fires ──► audit_logs (source='trigger')
  │
  └── audit.log() ──► Redis Queue (BullMQ)
                           │
                     Audit Worker (concurrency=1)
                           │
                     Fetch prev_hash
                           │
                     Compute SHA-256 row_hash
                           │
                     INSERT audit_logs (source='app')
```

---

## Project Structure

```
nodejs-audit-log-enterprise/
├── db/
│   ├── index.js                  # PostgreSQL pool
│   └── schema.sql                # Full schema + trigger
├── src/
│   ├── middleware/
│   │   └── auditContext.js       # Set session vars for trigger
│   ├── queue/
│   │   └── auditQueue.js         # BullMQ async queue + worker
│   ├── routes/
│   │   └── records.js            # Example CRUD routes with audit logging
│   ├── services/
│   │   └── auditService.js       # Core audit writer with hash chaining
│   └── utils/
│       └── hashChain.js          # SHA-256 hash computation
├── scripts/
│   ├── verifyChain.js            # Integrity verification
│   └── archiveLogs.js            # Monthly archive to Azure Blob
├── app.js
├── server.js
└── .env.example
```

---

## Quick Start

### 1. Clone and install
```bash
git clone https://github.com/ziaongit/nodejs-audit-log-enterprise.git
cd nodejs-audit-log-enterprise
npm install
```

### 2. Set up PostgreSQL
```bash
createdb auditdemo
psql auditdemo < db/schema.sql
```

### 3. Configure environment
```bash
cp .env.example .env
# Edit .env with your DB credentials
```

### 4. Run
```bash
npm start
# Server running on port 3000
```

### 5. Test the audit log
```bash
# Create a record
curl -X POST http://localhost:3000/api/records \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{"name": "Test Record", "data": {"key": "value"}}'

# Query audit log
curl http://localhost:3000/api/records/audit \
  -H "Authorization: Bearer YOUR_JWT"
```

### 6. Verify chain integrity
```bash
npm run verify-chain
# Chain intact. 12 records verified.
```

---

## Compliance Mapping

| Requirement | Standard | Field |
|-------------|----------|-------|
| Who accessed/modified data | GDPR Art. 30 | `user_id`, `user_email`, `action` |
| Access control evidence | SOC 2 CC6.1 | `user_role`, `ip_address` |
| Record integrity | SOC 2 CC7.1 | `prev_hash`, `row_hash` |
| Log retention | HIPAA 164.312 | Archive script |
| Change management | ISO 27001 A.12.4 | `old_values`, `new_values` |

---

## Author

**Zia Ullah** — Full Stack Developer at [ValueAdd Solution Scandinavia AB](https://www.valueadd.se/)

Connect on [LinkedIn](https://www.linkedin.com/in/zia-ullah/) · [DevOps.com](https://devops.com/author/zia-ullah/) · [freeCodeCamp](https://www.freecodecamp.org/news/author/ziaullahzia/)
