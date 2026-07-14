-- ============================================================
-- Enterprise Audit Log Schema
-- ============================================================

-- Main audit log table (append-only)
CREATE TABLE audit_logs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sequence_num  BIGSERIAL NOT NULL,
  user_id       UUID NOT NULL,
  user_email    TEXT NOT NULL,
  user_role     TEXT NOT NULL,
  action        TEXT NOT NULL,          -- 'CREATE' | 'UPDATE' | 'DELETE' | 'VIEW'
  resource      TEXT NOT NULL,
  resource_id   TEXT,
  old_values    JSONB,
  new_values    JSONB,
  reason        TEXT,
  ip_address    INET,
  user_agent    TEXT,
  source        TEXT NOT NULL DEFAULT 'app',  -- 'app' | 'trigger' | 'migration'
  prev_hash     TEXT,
  row_hash      TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user_id    ON audit_logs(user_id);
CREATE INDEX idx_audit_resource   ON audit_logs(resource, resource_id);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_sequence   ON audit_logs(sequence_num);
CREATE INDEX idx_audit_action     ON audit_logs(action);

-- Archive table (same structure)
CREATE TABLE audit_logs_archive (LIKE audit_logs INCLUDING ALL);

-- ============================================================
-- Database-level tamper protection
-- ============================================================
-- Run as superuser after creating app_user:
-- REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM app_user;
-- REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs_archive FROM app_user;

-- Dedicated users (run as superuser):
-- CREATE USER audit_writer WITH PASSWORD 'strong_password_here';
-- GRANT INSERT ON audit_logs TO audit_writer;
-- GRANT USAGE ON SEQUENCE audit_logs_sequence_num_seq TO audit_writer;

-- CREATE USER audit_reader WITH PASSWORD 'another_strong_password';
-- GRANT SELECT ON audit_logs TO audit_reader;
-- GRANT SELECT ON audit_logs_archive TO audit_reader;

-- ============================================================
-- Example resource table (replace with your own)
-- ============================================================
CREATE TABLE IF NOT EXISTS records (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        VARCHAR(255) NOT NULL,
  data        JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- PostgreSQL Trigger — catches direct DB writes
-- ============================================================
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO audit_logs
      (user_id, user_email, user_role, action, resource, resource_id,
       new_values, source, created_at)
    VALUES (
      COALESCE(current_setting('app.current_user_id', true), '00000000-0000-0000-0000-000000000000')::UUID,
      COALESCE(current_setting('app.current_user_email', true), 'db-direct'),
      COALESCE(current_setting('app.current_user_role',  true), 'db-direct'),
      'CREATE', TG_TABLE_NAME, NEW.id::TEXT,
      row_to_json(NEW)::JSONB, 'trigger', NOW()
    );

  ELSIF TG_OP = 'UPDATE' THEN
    INSERT INTO audit_logs
      (user_id, user_email, user_role, action, resource, resource_id,
       old_values, new_values, source, created_at)
    VALUES (
      COALESCE(current_setting('app.current_user_id', true), '00000000-0000-0000-0000-000000000000')::UUID,
      COALESCE(current_setting('app.current_user_email', true), 'db-direct'),
      COALESCE(current_setting('app.current_user_role',  true), 'db-direct'),
      'UPDATE', TG_TABLE_NAME, NEW.id::TEXT,
      row_to_json(OLD)::JSONB, row_to_json(NEW)::JSONB, 'trigger', NOW()
    );

  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO audit_logs
      (user_id, user_email, user_role, action, resource, resource_id,
       old_values, source, created_at)
    VALUES (
      COALESCE(current_setting('app.current_user_id', true), '00000000-0000-0000-0000-000000000000')::UUID,
      COALESCE(current_setting('app.current_user_email', true), 'db-direct'),
      COALESCE(current_setting('app.current_user_role',  true), 'db-direct'),
      'DELETE', TG_TABLE_NAME, OLD.id::TEXT,
      row_to_json(OLD)::JSONB, 'trigger', NOW()
    );
  END IF;

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Attach trigger to your tables
CREATE TRIGGER audit_records_trigger
  AFTER INSERT OR UPDATE OR DELETE ON records
  FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();
