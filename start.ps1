$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "    Starting CyberVerse Multi-Agent Platform" -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Backend:  http://localhost:8000"
Write-Host "Frontend: http://localhost:5173"
Write-Host ""
Write-Host "Both services run in THIS window - logs from both will be interleaved below."
Write-Host "Press Ctrl+C (or close this window) to stop both servers."
Write-Host "==================================================="
Write-Host ""

# -NoNewWindow keeps the backend attached to this same console instead of spawning
# a separate window/tab (unlike batch's `start`, which Windows 11's Windows Terminal
# can hijack into a new window even when /b is passed).
#
# Uses `uv run python -m uvicorn ...` (not `uv run uvicorn ...`) - on some uv
# versions, passing uvicorn directly hits a bug where the `:` in `main:app` gets
# misparsed as a script path and fails with "Failed to canonicalize script path".
$backend = Start-Process -FilePath "cmd.exe" `
    -ArgumentList "/c", "python -m uvicorn src.fake_certificate_verification_agent.main:app --reload --port 8000" `
    -WorkingDirectory (Join-Path $root "backend") `
    -NoNewWindow -PassThru

try {
    Push-Location (Join-Path $root "frontend")
    npm run dev
} finally {
    Pop-Location
    if (-not $backend.HasExited) {
        Write-Host "`nStopping backend server..."
        Stop-Process -Id $backend.Id -Force -ErrorAction SilentlyContinue
    }
}
