# Build playgate.exe (single-file Windows app).
#
#   pip install pyinstaller
#   ./packaging/build.ps1
#
# Output: dist/playgate.exe   (double-click to open the web UI)

$ErrorActionPreference = "Stop"
# PyInstaller logs to stderr; Windows PowerShell 5.1 would treat that as an error
# under "Stop", so judge the build by its exit code instead.
Set-Location (Split-Path $PSScriptRoot -Parent)   # repo root

if (-not (Test-Path packaging/playgate.ico)) { python packaging/make_icon.py }

$ErrorActionPreference = "Continue"
python -m PyInstaller `
  --noconfirm `
  --onefile `
  --name playgate `
  --icon packaging/playgate.ico `
  --add-data "playgate/ui.html;playgate" `
  --add-data "playgate/data;playgate/data" `
  --collect-submodules playgate `
  packaging/playgate_launcher.py 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed ($LASTEXITCODE)" }
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Done. Run: dist\playgate.exe" -ForegroundColor Green
