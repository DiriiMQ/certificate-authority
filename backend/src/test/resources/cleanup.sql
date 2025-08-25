-- Cleanup script for test database
DELETE FROM public.key_rotation_log;
DELETE FROM public.audit_log;
DELETE FROM public.signing_keys;

-- Reset sequences if needed (H2 database)
ALTER SEQUENCE IF EXISTS hibernate_sequence RESTART WITH 1;