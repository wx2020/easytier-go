# ==============================================================================
# Standalone IPK builder for luci-app-easytier (Windows PowerShell)
# ==============================================================================
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $scriptDir "build"
$outputDir = Join-Path $scriptDir "bin"

$pkgName = "luci-app-easytier"
$pkgVer = "1.0.1"
$pkgRel = "1"
$pkgArch = "aarch64_generic"
$ipkFile = "${pkgName}_${pkgVer}-${pkgRel}_${pkgArch}.ipk"
$tarFile = "${pkgName}-files-${pkgVer}.tar.gz"

Write-Host "==> Cleaning previous build artifacts..." -ForegroundColor Cyan
if (Test-Path $buildDir) { Remove-Item -Recurse -Force $buildDir }
if (Test-Path $outputDir) { Remove-Item -Recurse -Force $outputDir }
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $buildDir "data") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $buildDir "control") | Out-Null
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

# Resolve Go source directory
$repoGo = $null
$candidatePaths = @(
    (Join-Path $scriptDir "..\easytier-go\go"),
    (Join-Path $scriptDir "..\go"),
    "C:\Users\J6001887\Code\mine\easytier-go\go"
)
foreach ($cand in $candidatePaths) {
    if (Test-Path $cand) {
        $repoGo = (Resolve-Path $cand).Path
        break
    }
}

Write-Host "==> Building EasyTier Go for linux/arm64..." -ForegroundColor Cyan
if ($repoGo -and (Test-Path $repoGo)) {
    Write-Host "    Using Go source at: $repoGo" -ForegroundColor DarkGray
    Push-Location $repoGo
    try {
        $env:CGO_ENABLED = "0"
        $env:GOOS = "linux"
        $env:GOARCH = "arm64"
        & go build -trimpath -ldflags "-s -w -X main.version=v${pkgVer}" -o (Join-Path $buildDir "easytier-core") ./cmd/easytier-core
        & go build -trimpath -ldflags "-s -w -X main.version=v${pkgVer}" -o (Join-Path $buildDir "easytier-cli") ./cmd/easytier-cli
    } finally {
        Pop-Location
    }
} else {
    throw "Go source directory not found in candidate paths: $($candidatePaths -join ', ')"
}

Copy-Item (Join-Path $buildDir "easytier-core") (Join-Path $outputDir "easytier-core")
Copy-Item (Join-Path $buildDir "easytier-cli") (Join-Path $outputDir "easytier-cli")

Write-Host "==> Staging data..." -ForegroundColor Cyan
Copy-Item -Recurse -Force (Join-Path $scriptDir "root\*") (Join-Path $buildDir "data")
$targetBinDir = Join-Path $buildDir "data\usr\bin"
if (!(Test-Path $targetBinDir)) { New-Item -ItemType Directory -Force -Path $targetBinDir | Out-Null }
Copy-Item (Join-Path $buildDir "easytier-core") (Join-Path $targetBinDir "easytier-core")
Copy-Item (Join-Path $buildDir "easytier-cli") (Join-Path $targetBinDir "easytier-cli")

Write-Host "==> Staging control..." -ForegroundColor Cyan
Copy-Item -Recurse -Force (Join-Path $scriptDir "control\*") (Join-Path $buildDir "control")
[System.IO.File]::WriteAllText((Join-Path $buildDir "debian-binary"), "2.0`n", (New-Object System.Text.UTF8Encoding($false)))

Write-Host "==> Creating archives..." -ForegroundColor Cyan
$controlDir = Join-Path $buildDir "control"
tar -czf (Join-Path $buildDir "control.tar.gz") -C $controlDir .

$dataDir = Join-Path $buildDir "data"
tar -czf (Join-Path $buildDir "data.tar.gz") -C $dataDir .

Write-Host "==> Packaging into ${ipkFile}..." -ForegroundColor Cyan
$targetIpk = Join-Path $outputDir $ipkFile
tar -czf $targetIpk -C $buildDir debian-binary control.tar.gz data.tar.gz

Write-Host "==> Packaging into ${tarFile}..." -ForegroundColor Cyan
$targetTar = Join-Path $outputDir $tarFile
tar -czf $targetTar -C $dataDir .

Write-Host "==> Build successful!" -ForegroundColor Green
Write-Host "    Output IPK:     $targetIpk" -ForegroundColor Yellow
Write-Host "    Output Payload: $targetTar" -ForegroundColor Yellow
Get-ChildItem $outputDir | Select-Object Name, Length, LastWriteTime
