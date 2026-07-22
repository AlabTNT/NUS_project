[CmdletBinding()]
param(
    [string]$Python = ".\.venv\Scripts\python.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Python was not found at: $Python. Create the virtual environment as described in README.md."
}

& $Python -m pip install "pyinstaller>=6,<7"
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller installation failed with exit code $LASTEXITCODE."
}

& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --console `
    --name "door-lock-sim" `
    --collect-submodules "smartcard" `
    ".\door_lock_sim.py"
if ($LASTEXITCODE -ne 0) {
    throw "EXE build failed with exit code $LASTEXITCODE."
}

Write-Host "Build complete: $((Resolve-Path '.\dist\door-lock-sim.exe').Path)"
