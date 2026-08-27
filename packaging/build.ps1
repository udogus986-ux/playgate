# Build playgate.exe (single-file Windows app).
#
#   pip install pyinstaller
#   ./packaging/build.ps1
#
# Output: dist/playgate.exe   (double-click to open the web UI)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)   # repo root

pyinstaller `
  --noconfirm `
  --onefile `
  --name playgate `
  --add-data "playgate/ui.html;playgate" `
  --collect-submodules playgate.rules `
  --hidden-import playgate.inputs.package `
  --hidden-import playgate.proto `
  --hidden-import playgate.mcp `
  --hidden-import playgate.webui `
  packaging/playgate_launcher.py

Write-Host ""
Write-Host "Done. Run: dist\playgate.exe" -ForegroundColor Green
