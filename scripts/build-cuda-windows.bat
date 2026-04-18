@echo off
setlocal enabledelayedexpansion

REM Build malairted-windows-amd64-cuda.exe.
REM Requires VS 2022 / 2026 with the C++ workload, CUDA Toolkit, Go 1.22+,
REM and MinGW gcc on PATH (for CGO link).

REM --- Locate vcvars64.bat ---------------------------------------------------
set "VCVARS="
set "VS22BT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "VS18=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
set "VS22C=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set "VS22P=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
set "VS22E=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
REM Prefer VS 2026 (v18) if present, then VS 2022 editions, then BuildTools.
if exist "%VS18%"  set "VCVARS=%VS18%"
if not defined VCVARS if exist "%VS22C%" set "VCVARS=%VS22C%"
if not defined VCVARS if exist "%VS22P%" set "VCVARS=%VS22P%"
if not defined VCVARS if exist "%VS22E%" set "VCVARS=%VS22E%"
if not defined VCVARS if exist "%VS22BT%" set "VCVARS=%VS22BT%"
if not defined VCVARS (
    echo ERROR: vcvars64.bat not found. Install VS 2022+ with C++ workload.
    exit /b 1
)

echo Using "%VCVARS%"
call "%VCVARS%" >nul

REM --- Resolve repo root (parent of scripts\) ------------------------------
pushd "%~dp0.."
set "REPO=%CD%"
popd

REM --- Preflight -----------------------------------------------------------
where nvcc >nul 2>&1 || (echo ERROR: nvcc not on PATH & exit /b 2)
where go   >nul 2>&1 || (echo ERROR: go not on PATH   & exit /b 3)
where gcc  >nul 2>&1 || (echo ERROR: gcc not on PATH ^(needed for CGO^)  & exit /b 4)

REM --- Build the CUDA kernel as a self-contained DLL -----------------------
REM MSVC-produced objects embed intrinsics (__security_cookie, __GSHandlerCheck,
REM _Init_thread_epoch, etc.) that MinGW's linker can't resolve. The workaround
REM is to let MSVC link.exe produce a self-contained DLL with the CUDA runtime
REM statically embedded, then have MinGW/Go link against the DLL's export table.
cd /d "%REPO%\internal\mining\cuda"
echo Building CUDA kernel as DLL ...

if defined CUDA_PATH (
    set "CUDA_LIB=%CUDA_PATH%\lib\x64"
) else (
    set "CUDA_LIB=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.2\lib\x64"
)

nvcc -O3 --use_fast_math --std=c++17 ^
  -gencode=arch=compute_75,code=sm_75 ^
  -gencode=arch=compute_86,code=sm_86 ^
  -gencode=arch=compute_89,code=sm_89 ^
  -gencode=arch=compute_90,code=sm_90 ^
  -gencode=arch=compute_90,code=compute_90 ^
  -Xcompiler /MT ^
  -c mlrt_gpu.cu -o mlrt_gpu.obj
if errorlevel 1 (echo ERROR: nvcc failed & exit /b 5)

REM Write an explicit export list so only our C-ABI surface is exposed.
> exports.def (
  echo LIBRARY mlrt_gpu.dll
  echo EXPORTS
  echo   mlrt_gpu_init
  echo   mlrt_gpu_shutdown
  echo   mlrt_gpu_mine
  echo   mlrt_cpu_hash
)

link /nologo /DLL /OUT:mlrt_gpu.dll /IMPLIB:mlrt_gpu.lib ^
  /DEF:exports.def ^
  mlrt_gpu.obj ^
  "%CUDA_LIB%\cudart_static.lib" ^
  advapi32.lib user32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib kernel32.lib
if errorlevel 1 (echo ERROR: link failed & exit /b 6)

REM Write a tiny MinGW-compatible import lib from the .def so CGO can link it.
dlltool -d exports.def -l libmlrtgpu.a -D mlrt_gpu.dll
if errorlevel 1 (echo ERROR: dlltool failed & exit /b 7)

echo OK: mlrt_gpu.dll built ^(self-contained^) + libmlrtgpu.a import lib.

REM --- Build malairted with cgo+cuda tag -----------------------------------
cd /d "%REPO%"
echo Building malairted-windows-amd64-cuda.exe ...
set CGO_ENABLED=1

REM Find CUDA lib path so the MinGW linker can resolve cudart_static.lib.
if defined CUDA_PATH (
    set "CUDA_LIB=%CUDA_PATH%\lib\x64"
) else (
    set "CUDA_LIB=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.2\lib\x64"
)
if not exist "%CUDA_LIB%\cudart_static.lib" (
    echo ERROR: cannot find cudart_static.lib under "%CUDA_LIB%"
    exit /b 8
)

REM Go cgo_ldflag parser splits on spaces and rejects quoted args, so convert
REM to an 8.3 short path without spaces.
for %%A in ("%CUDA_LIB%") do set "CUDA_LIB_SHORT=%%~sA"
echo CUDA lib path: %CUDA_LIB_SHORT%
set CGO_LDFLAGS=-L%CUDA_LIB_SHORT%

go build -tags cuda -ldflags "-s -w" -o malairted-windows-amd64-cuda.exe .\cmd\malairted
if errorlevel 1 (echo ERROR: go build failed & exit /b 7)

for %%A in (malairted-windows-amd64-cuda.exe) do set SZ=%%~zA
echo.
echo OK: malairted-windows-amd64-cuda.exe built ^(!SZ! bytes^)
echo Run it:  malairted-windows-amd64-cuda.exe --mine --gpu --miner-key=^<key^>
endlocal
