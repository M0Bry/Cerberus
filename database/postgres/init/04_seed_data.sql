-- Initial seed data (roles, permissions, admin)
-- NOTE: Admin password is set via the seed script, not here.
-- Run: python -m scripts.create_admin
-- This SQL only creates the user record; the password hash is generated at runtime.
INSERT INTO users (id, email, password_hash, role, status, full_name, company_name, job_title, email_verified_at)
VALUES (
    gen_random_uuid(),
    'admin@cerberus-ai.com',
    '$argon2id$PLACEHOLDER_GENERATE_VIA_SEED_SCRIPT',
    'super_admin',
    'verified',
    'System Administrator',
    'Cerberus AI',
    'Platform Administrator',
    NOW()
) ON CONFLICT (email) DO NOTHING;
