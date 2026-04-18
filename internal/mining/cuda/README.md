# CUDA GPU miner for MLRTHash

Native CUDA implementation of DoubleSHA3256, linked into `malairted` via CGO.
CPU-only builds ignore this directory completely.

## Prerequisites

- NVIDIA GPU (compute capability 7.0+)
- NVIDIA CUDA Toolkit 12.x or 13.x  (provides `nvcc`)
- Go 1.22+ with `CGO_ENABLED=1`
- GCC / MSVC depending on platform

## Pick the right `CUDA_ARCH`

| GPU family        | `-arch=` flag       |
|-------------------|---------------------|
| RTX 20xx (Turing) | `sm_75`             |
| RTX 30xx (Ampere) | `sm_86`             |
| RTX 40xx (Ada)    | `sm_89` *(default)* |
| RTX 50xx (Blackwell, CUDA 12.8+) | `sm_120` |
| H100 (Hopper)     | `sm_90`             |

For a 5090 with CUDA Toolkit 13.x: `make CUDA_ARCH=sm_120`.
On CUDA 12.x the 5090 is forward-compatible from `sm_90`.

## Build

```bash
# 1. Compile the CUDA object into a static library.
cd internal/mining/cuda
make CUDA_ARCH=sm_120       # adjust for your card

# 2. (Optional) self-test the hash against the Go reference.
make selftest               # prints DoubleSHA3256 of "", "abc", zeros[96]
go run ./reference          # same inputs, Go's crypto.DoubleSHA3256
#   → all three hashes must match byte-for-byte

# 3. Build malairted with the cuda tag.
cd ../../..
CGO_ENABLED=1 go build -tags cuda -o malairted.exe ./cmd/malairted
```

## Run

```bash
./malairted.exe --mine --gpu --miner-key=<64-hex-key>
```

Expected log on startup:

```
[mlrt_gpu] device 0: NVIDIA GeForce RTX 5090  (170 SMs, 31.8 GB)
[miner/gpu] worker running
```

The GPU worker starts from `extraNonce = 2^32` so it never collides with
the CPU threads (which start from thread-ID offsets). Every kernel launch
tries 16 M nonces in ~30 ms on modern hardware; the count is added to the
shared `totalHashes` counter so the RPC `hashespersec` reading aggregates
CPU + GPU hashrate.

## Debugging a hash mismatch

If the kernel reports a hit that the CPU rejects (`[miner/gpu] BUG:` log),
the kernel math is off. The driver dumps the full header, target, and CPU
hash. Feed that header into `go run ./reference` with modified input to
reproduce on Go side.

Most common causes:
- Wrong endianness when packing bytes into lanes
- Off-by-one in the padding position (byte 96 vs 95, byte 135 vs 136)
- `sm_` arch too low for the instructions compiled

## Uninstall

```bash
make clean
```

Removes `libmlrtgpu.a` and the object file. The Go stub build then takes
over automatically on subsequent `go build`s without the `cuda` tag.
