-- Cerberus AI — Database Roles (Least Privilege)
-- Application role: read/write access to cerberus tables
CREATE ROLE cerberus_app WITH LOGIN PASSWORD 'REPLACE_WITH_PASSWORD' NOSUPERUSER NOCREATEDB NOCREATEROLE;
-- Read-only role: for reporting/analytics
CREATE ROLE cerberus_readonly WITH LOGIN PASSWORD 'REPLACE_WITH_PASSWORD' NOSUPERUSER NOCREATEDB NOCREATEROLE;
-- Admin role: elevated but NOT superuser
CREATE ROLE cerberus_admin WITH LOGIN PASSWORD 'REPLACE_WITH_PASSWORD' NOSUPERUSER CREATEDB NOCREATEROLE;
