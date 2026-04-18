/*
 * CUDA implementation of MLRTHash v1 = DoubleSHA3256(block_header).
 *
 * Header layout (96 bytes, little-endian numeric fields):
 *   [ 0..3]  version
 *   [ 4..35] previous hash
 *   [36..67] merkle root
 *   [68..75] timestamp
 *   [76..79] bits
 *   [80..87] nonce      <- search variable
 *   [88..95] height
 *
 * The target is a 32-byte big-endian integer. A candidate hash is valid iff,
 * interpreted as a big-endian 256-bit integer, hash <= target.
 *
 * Kernel layout: one thread per candidate nonce. Each thread keeps a local
 * 96-byte header copy, overwrites the nonce bytes, runs two Keccak-f[1600]
 * permutations, and atomically claims the first match.
 */

#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mlrt_gpu.h"

/* ── Keccak primitives ────────────────────────────────────────────────────── */

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

__device__ __constant__ uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Host copy of the constants so mlrt_cpu_hash can run on CPU. */
static const uint64_t HOST_KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

#define KECCAK_F1600_BODY(A)                                                                  \
    do {                                                                                      \
        uint64_t C0, C1, C2, C3, C4, D0, D1, D2, D3, D4;                                      \
        uint64_t B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12;                       \
        uint64_t B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24;                  \
        for (int r = 0; r < 24; r++) {                                                        \
            C0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];                                         \
            C1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];                                         \
            C2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];                                         \
            C3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];                                         \
            C4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];                                         \
            D0 = C4 ^ ROTL64(C1, 1); D1 = C0 ^ ROTL64(C2, 1);                                 \
            D2 = C1 ^ ROTL64(C3, 1); D3 = C2 ^ ROTL64(C4, 1);                                 \
            D4 = C3 ^ ROTL64(C0, 1);                                                          \
            A[0]  ^= D0; A[5]  ^= D0; A[10] ^= D0; A[15] ^= D0; A[20] ^= D0;                  \
            A[1]  ^= D1; A[6]  ^= D1; A[11] ^= D1; A[16] ^= D1; A[21] ^= D1;                  \
            A[2]  ^= D2; A[7]  ^= D2; A[12] ^= D2; A[17] ^= D2; A[22] ^= D2;                  \
            A[3]  ^= D3; A[8]  ^= D3; A[13] ^= D3; A[18] ^= D3; A[23] ^= D3;                  \
            A[4]  ^= D4; A[9]  ^= D4; A[14] ^= D4; A[19] ^= D4; A[24] ^= D4;                  \
            B0  = A[0];                                                                       \
            B10 = ROTL64(A[1],  1);  B20 = ROTL64(A[2],  62);                                 \
            B5  = ROTL64(A[3], 28);  B15 = ROTL64(A[4],  27);                                 \
            B16 = ROTL64(A[5], 36);  B1  = ROTL64(A[6],  44);                                 \
            B11 = ROTL64(A[7],  6);  B21 = ROTL64(A[8],  55);                                 \
            B6  = ROTL64(A[9], 20);  B7  = ROTL64(A[10],  3);                                 \
            B17 = ROTL64(A[11], 10); B2  = ROTL64(A[12], 43);                                 \
            B12 = ROTL64(A[13], 25); B22 = ROTL64(A[14], 39);                                 \
            B23 = ROTL64(A[15], 41); B8  = ROTL64(A[16], 45);                                 \
            B18 = ROTL64(A[17], 15); B3  = ROTL64(A[18], 21);                                 \
            B13 = ROTL64(A[19],  8); B14 = ROTL64(A[20], 18);                                 \
            B24 = ROTL64(A[21],  2); B9  = ROTL64(A[22], 61);                                 \
            B19 = ROTL64(A[23], 56); B4  = ROTL64(A[24], 14);                                 \
            A[0]  = B0  ^ ((~B1)  & B2);                                                      \
            A[1]  = B1  ^ ((~B2)  & B3);                                                      \
            A[2]  = B2  ^ ((~B3)  & B4);                                                      \
            A[3]  = B3  ^ ((~B4)  & B0);                                                      \
            A[4]  = B4  ^ ((~B0)  & B1);                                                      \
            A[5]  = B5  ^ ((~B6)  & B7);                                                      \
            A[6]  = B6  ^ ((~B7)  & B8);                                                      \
            A[7]  = B7  ^ ((~B8)  & B9);                                                      \
            A[8]  = B8  ^ ((~B9)  & B5);                                                      \
            A[9]  = B9  ^ ((~B5)  & B6);                                                      \
            A[10] = B10 ^ ((~B11) & B12);                                                     \
            A[11] = B11 ^ ((~B12) & B13);                                                     \
            A[12] = B12 ^ ((~B13) & B14);                                                     \
            A[13] = B13 ^ ((~B14) & B10);                                                     \
            A[14] = B14 ^ ((~B10) & B11);                                                     \
            A[15] = B15 ^ ((~B16) & B17);                                                     \
            A[16] = B16 ^ ((~B17) & B18);                                                     \
            A[17] = B17 ^ ((~B18) & B19);                                                     \
            A[18] = B18 ^ ((~B19) & B15);                                                     \
            A[19] = B19 ^ ((~B15) & B16);                                                     \
            A[20] = B20 ^ ((~B21) & B22);                                                     \
            A[21] = B21 ^ ((~B22) & B23);                                                     \
            A[22] = B22 ^ ((~B23) & B24);                                                     \
            A[23] = B23 ^ ((~B24) & B20);                                                     \
            A[24] = B24 ^ ((~B20) & B21);                                                     \
            A[0] ^= rc_ptr[r];                                                                \
        }                                                                                     \
    } while (0)

/* ── Device helpers ───────────────────────────────────────────────────────── */

__device__ __forceinline__ void sha3_256_96_device(const uint8_t header[96], uint8_t out[32]) {
    uint64_t A[25];
    #pragma unroll
    for (int i = 0; i < 25; i++) A[i] = 0;

    /* Absorb 96 bytes = 12 lanes (little-endian). */
    #pragma unroll
    for (int i = 0; i < 12; i++) {
        uint64_t lane = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) lane |= ((uint64_t)header[i*8 + j]) << (j*8);
        A[i] = lane;
    }
    /* Padding: SHA3 domain sep 0x06 at byte 96 (lane 12 low byte),
     *          final bit 0x80 at byte 135 (lane 16 high byte of the 17-lane rate). */
    A[12] ^= 0x06ULL;
    A[16] ^= 0x8000000000000000ULL;

    const uint64_t* rc_ptr = KECCAK_RC;
    KECCAK_F1600_BODY(A);

    /* Squeeze 32 bytes = 4 lanes. */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        uint64_t lane = A[i];
        #pragma unroll
        for (int j = 0; j < 8; j++) out[i*8 + j] = (uint8_t)(lane >> (j*8));
    }
}

__device__ __forceinline__ void sha3_256_32_device(const uint8_t in[32], uint8_t out[32]) {
    uint64_t A[25];
    #pragma unroll
    for (int i = 0; i < 25; i++) A[i] = 0;

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        uint64_t lane = 0;
        #pragma unroll
        for (int j = 0; j < 8; j++) lane |= ((uint64_t)in[i*8 + j]) << (j*8);
        A[i] = lane;
    }
    A[4]  ^= 0x06ULL;
    A[16] ^= 0x8000000000000000ULL;

    const uint64_t* rc_ptr = KECCAK_RC;
    KECCAK_F1600_BODY(A);

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        uint64_t lane = A[i];
        #pragma unroll
        for (int j = 0; j < 8; j++) out[i*8 + j] = (uint8_t)(lane >> (j*8));
    }
}

/* ── Mining kernel ────────────────────────────────────────────────────────── */

__global__ void mine_kernel(
    const uint8_t* __restrict__ header_template,
    const uint8_t* __restrict__ target,
    uint64_t                    start_nonce,
    uint64_t*                   out_nonce,
    int*                        out_found)
{
    /* Short-circuit if another thread already won — best-effort, not a barrier. */
    if (*out_found) return;

    const uint64_t idx   = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    const uint64_t nonce = start_nonce + idx;

    /* Local header copy (register/local memory). */
    uint8_t hdr[96];
    #pragma unroll
    for (int i = 0; i < 96; i++) hdr[i] = header_template[i];

    /* Overwrite nonce (little-endian, 8 bytes at offset 80). */
    hdr[80] = (uint8_t)(nonce      );
    hdr[81] = (uint8_t)(nonce >>  8);
    hdr[82] = (uint8_t)(nonce >> 16);
    hdr[83] = (uint8_t)(nonce >> 24);
    hdr[84] = (uint8_t)(nonce >> 32);
    hdr[85] = (uint8_t)(nonce >> 40);
    hdr[86] = (uint8_t)(nonce >> 48);
    hdr[87] = (uint8_t)(nonce >> 56);

    uint8_t h1[32];
    uint8_t h2[32];
    sha3_256_96_device(hdr, h1);
    sha3_256_32_device(h1, h2);

    /* Compare h2 and target as big-endian 256-bit integers.
     * The Go consensus layer uses big.Int.SetBytes(hash[:]) which is big-endian. */
    int ge = 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (h2[i] < target[i]) { ge = 0; break; }
        if (h2[i] > target[i]) { ge = 1; break; }
    }

    if (!ge) {
        /* atomicExch returns the old value; only the first thread to flip 0->1 wins. */
        if (atomicExch(out_found, 1) == 0) {
            *out_nonce = nonce;
        }
    }
}

/* ── Host-side helpers ────────────────────────────────────────────────────── */

static uint8_t* d_header = NULL;
static uint8_t* d_target = NULL;
static uint64_t* d_nonce = NULL;
static int*      d_found = NULL;
static int       g_device = -1;

static int check(cudaError_t e, const char* where) {
    if (e == cudaSuccess) return 0;
    fprintf(stderr, "[mlrt_gpu] CUDA error in %s: %s\n", where, cudaGetErrorString(e));
    return -1;
}

extern "C" int mlrt_gpu_init(void) {
    int count = 0;
    if (check(cudaGetDeviceCount(&count), "cudaGetDeviceCount")) return -1;
    if (count == 0) {
        fprintf(stderr, "[mlrt_gpu] no CUDA devices found\n");
        return -2;
    }

    g_device = 0;
    if (check(cudaSetDevice(g_device), "cudaSetDevice")) return -3;

    cudaDeviceProp prop;
    if (check(cudaGetDeviceProperties(&prop, g_device), "cudaGetDeviceProperties")) return -4;
    fprintf(stdout, "[mlrt_gpu] device 0: %s  (%d SMs, %.1f GB)\n",
            prop.name, prop.multiProcessorCount,
            (double)prop.totalGlobalMem / (1024.0*1024.0*1024.0));

    if (check(cudaMalloc(&d_header, 96), "cudaMalloc header"))  return -5;
    if (check(cudaMalloc(&d_target, 32), "cudaMalloc target"))  return -6;
    if (check(cudaMalloc(&d_nonce, sizeof(uint64_t)), "cudaMalloc nonce")) return -7;
    if (check(cudaMalloc(&d_found, sizeof(int)),      "cudaMalloc found")) return -8;
    return 0;
}

extern "C" void mlrt_gpu_shutdown(void) {
    if (d_header) { cudaFree(d_header); d_header = NULL; }
    if (d_target) { cudaFree(d_target); d_target = NULL; }
    if (d_nonce)  { cudaFree(d_nonce);  d_nonce  = NULL; }
    if (d_found)  { cudaFree(d_found);  d_found  = NULL; }
    g_device = -1;
}

extern "C" int mlrt_gpu_mine(
    const uint8_t* header,
    const uint8_t* target,
    uint64_t       start_nonce,
    uint64_t       batch_size,
    uint64_t*      out_nonce,
    int*           out_found)
{
    if (g_device < 0) return -1;
    if (batch_size == 0 || (batch_size % 256) != 0) return -2;

    int zero = 0;
    if (check(cudaMemcpy(d_header, header, 96, cudaMemcpyHostToDevice), "memcpy header")) return -3;
    if (check(cudaMemcpy(d_target, target, 32, cudaMemcpyHostToDevice), "memcpy target")) return -4;
    if (check(cudaMemcpy(d_found,  &zero,  sizeof(int), cudaMemcpyHostToDevice), "memcpy found")) return -5;

    const int threads_per_block = 256;
    const uint64_t blocks       = batch_size / threads_per_block;

    mine_kernel<<<(unsigned int)blocks, threads_per_block>>>(
        d_header, d_target, start_nonce, d_nonce, d_found);
    if (check(cudaGetLastError(), "kernel launch")) return -6;
    if (check(cudaDeviceSynchronize(), "kernel sync")) return -7;

    int host_found = 0;
    uint64_t host_nonce = 0;
    if (check(cudaMemcpy(&host_found, d_found, sizeof(int),      cudaMemcpyDeviceToHost), "memcpy found out")) return -8;
    if (host_found) {
        if (check(cudaMemcpy(&host_nonce, d_nonce, sizeof(uint64_t), cudaMemcpyDeviceToHost), "memcpy nonce out")) return -9;
    }
    *out_found = host_found;
    *out_nonce = host_nonce;
    return 0;
}

/* ── CPU reference (self-test) ────────────────────────────────────────────── */

static void keccak_f1600_host(uint64_t A[25]) {
    const uint64_t* rc_ptr = HOST_KECCAK_RC;
    KECCAK_F1600_BODY(A);
}

static void sha3_256_host(const uint8_t* in, uint32_t len, uint8_t out[32]) {
    uint64_t A[25];
    memset(A, 0, sizeof(A));

    const uint32_t rate_bytes = 136;
    uint32_t pos = 0;
    while (len >= rate_bytes) {
        for (uint32_t i = 0; i < rate_bytes/8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++) lane |= ((uint64_t)in[pos + i*8 + j]) << (j*8);
            A[i] ^= lane;
        }
        keccak_f1600_host(A);
        pos += rate_bytes;
        len -= rate_bytes;
    }

    /* Last (possibly empty) block with padding. */
    uint8_t block[136];
    memset(block, 0, rate_bytes);
    memcpy(block, in + pos, len);
    block[len]            ^= 0x06;
    block[rate_bytes - 1] ^= 0x80;
    for (uint32_t i = 0; i < rate_bytes/8; i++) {
        uint64_t lane = 0;
        for (int j = 0; j < 8; j++) lane |= ((uint64_t)block[i*8 + j]) << (j*8);
        A[i] ^= lane;
    }
    keccak_f1600_host(A);

    for (int i = 0; i < 4; i++) {
        uint64_t lane = A[i];
        for (int j = 0; j < 8; j++) out[i*8 + j] = (uint8_t)(lane >> (j*8));
    }
}

extern "C" void mlrt_cpu_hash(const uint8_t* input, uint32_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    sha3_256_host(input, len, tmp);
    sha3_256_host(tmp, 32, out);
}
