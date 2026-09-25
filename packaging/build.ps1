# Build playgate.exe (single-file Windows app).
#
#   pip install pyinstaller
#   ./packaging/build.ps1
#
# Output: dist/playgate.exe   (double-click to open the web UI)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)   # repo root

if (-not (Test-Path packaging/playgate.ico)) { python packaging/make_icon.py }

pyinstaller `
  --noconfirm `
  --onefile `
  --name playgate `
  --icon packaging/playgate.ico `
  --add-data "playgate/ui.html;playgate" `
  --add-data "playgate/data;playgate/data" `
  --collect-submodules playgate `
  packaging/playgate_launcher.py

Write-Host ""
Write-Host "Done. Run: dist\playgate.exe" -ForegroundColor Green
