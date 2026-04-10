# push_to_github.ps1
# Helper script to add, commit, and push changes to GitHub.
# Before running this, assure Git is installed and in your PATH.

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  PUSHING TO GITHUB" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

try {
    $gitVer = git --version 2>&1
    Write-Host "[OK] Git found: $gitVer" -ForegroundColor Green
} catch {
    Write-Host "[!!] Git is not reachable in the current PATH." -ForegroundColor Red
    Write-Host "     If using GitHub Desktop, please open it to commit and push the newly created files." -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Adding all files to Git..." -ForegroundColor Yellow
git add .

Write-Host "[*] Committing changes..." -ForegroundColor Yellow
git commit -m "Add interactive security dashboard and update landing page"

Write-Host "[*] Pushing to remote repository..." -ForegroundColor Yellow
git push

Write-Host "[OK] Successfully pushed!" -ForegroundColor Green
