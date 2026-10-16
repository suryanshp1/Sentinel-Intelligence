\getenv app_password VI_DB_PASSWORD
CREATE ROLE sentinel_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
ALTER ROLE sentinel_app PASSWORD :'app_password';
\ir /opt/sentinel/runtime-role.sql
