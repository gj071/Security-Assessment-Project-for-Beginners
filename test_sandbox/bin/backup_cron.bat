@echo off
REM Backup script with hardcoded credentials
set BACKUP_USER=admin
set BACKUP_PASS=backup_password_123
xcopy /s /e C:\data C:\backup
