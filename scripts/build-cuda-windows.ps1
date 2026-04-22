# Build a CUDA-enabled malairte-node.exe on Windows.
#
# Prerequisites:
#   - NVIDIA CUDA Toolkit 12.x or 13.x  (nvcc on PATH)
#   - Go 1.22+                          (go on PATH)
#   - A C toolchain that nvcc can drive:
#       * Visual Studio Build Tools 2019/2022, or
#       * MSYS2 mingw-w64 (set CC=gcc manually)
#
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\build-cuda-windows.ps1
#
# Produces:
#   malairte-node-windows-amd64-cuda.exe  (self-contained, no libcudart runtime needed)

$ErrorActionPreference = 'Stop'

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }
function Note($msg) { Write-Host $msg -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "OK: $msg" -ForegroundColor Green }

# Resolve repo root (parent of scripts/)
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

# ── Preflight ────────────────────────────────────────────────────────────────
if (-not (Get-Command nvcc -ErrorAction SilentlyContinue)) {
    Fail "nvcc not found on PATH. Install CUDA Toolkit from https://developer.nvidia.com/cuda-downloads"
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Fail "go not found on PATH. Install Go 1.22+ from https://go.dev/dl/"
}

$nvccVer = (& nvcc --version | Select-String 'release' | Out-String).Trim()
$goVer   = (& go version | Out-String).Trim()
Note "CUDA: $nvccVer"
Note "Go:   $goVer"

# ── Build libmlrtgpu.lib ─────────────────────────────────────────────────────
$cudaDir = Join-Path $RepoRoot 'internal\mining\cuda'
Set-Location $cudaDir
Note "Building CUDA kernel in $cudaDir ..."

$gencode = @(
    '-gencode=arch=compute_75,code=sm_75',
    '-gencode=arch=compute_86,code=sm_86',
    '-gencode=arch=compute_89,code=sm_89',
    '-gencode=arch=compute_90,code=sm_90',
    '-gencode=arch=compute_90,code=compute_90'  # PTX fallback for newer GPUs (e.g. sm_120)
)

& nvcc -O3 @gencode --use_fast_math --std=c++17 -c mlrt_gpu.cu -o mlrt_gpu.obj
if ($LASTEXITCODE -ne 0) { Fail "nvcc failed" }

# Create a static lib that CGO can link against.
& lib /OUT:libmlrtgpu.lib mlrt_gpu.obj 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    # lib.exe isn't on PATH -- try ar from mingw as fallback.
    & ar rcs libmlrtgpu.a mlrt_gpu.obj
    if ($LASTEXITCODE -ne 0) { Fail "both lib.exe and ar failed -- run from Developer Command Prompt or install mingw" }
}
Ok "CUDA library built"

# ── Build malairte-node.exe with -tags cuda ──────────────────────────────────────
Set-Location $RepoRoot
Note "Building malairte-node-windows-amd64-cuda.exe ..."
$env:CGO_ENABLED = '1'
& go build -tags cuda -o malairte-node-windows-amd64-cuda.exe .\cmd\malairte-node
if ($LASTEXITCODE -ne 0) { Fail "go build failed" }

$size = [math]::Round((Get-Item malairte-node-windows-amd64-cuda.exe).Length / 1MB, 1)
Ok "Built: malairte-node-windows-amd64-cuda.exe ($size MB)"
Write-Host ""
Write-Host "Run it:"
Write-Host "  .\malairte-node-windows-amd64-cuda.exe --mine --gpu --miner-key=<your-64-hex-key>" -ForegroundColor Yellow
