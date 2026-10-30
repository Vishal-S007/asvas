-- One-time local bootstrap, run as a PostgreSQL superuser (e.g. `sudo -u postgres psql -f scripts/db-bootstrap.sql`).
-- Development credentials only. In any shared environment, create roles with secrets from your secret manager.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'asvas_owner') THEN
    CREATE ROLE asvas_owner LOGIN PASSWORD 'asvas_owner_dev';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'asvas_app') THEN
    -- Application role: NOT owner, NOT superuser, NOBYPASSRLS => row-level security always applies.
    CREATE ROLE asvas_app LOGIN PASSWORD 'asvas_app_dev' NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'asvas_auth_definer') THEN
    -- Owns only the narrow SECURITY DEFINER identity-lookup function; cannot log in.
    CREATE ROLE asvas_auth_definer NOLOGIN BYPASSRLS;
  END IF;
  GRANT asvas_auth_definer TO asvas_owner;
END $$;
SELECT 'CREATE DATABASE asvas OWNER asvas_owner' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'asvas')\gexec
SELECT 'CREATE DATABASE asvas_test OWNER asvas_owner' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'asvas_test')\gexec
\c asvas
CREATE EXTENSION IF NOT EXISTS pgcrypto;
GRANT CONNECT ON DATABASE asvas TO asvas_app;
\c asvas_test
CREATE EXTENSION IF NOT EXISTS pgcrypto;
GRANT CONNECT ON DATABASE asvas_test TO asvas_app;
