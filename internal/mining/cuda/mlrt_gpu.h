#ifndef MLRT_GPU_H
#define MLRT_GPU_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 0 on success, negative on failure.
 * Probes the first CUDA device and prints its name to stdout. */
int mlrt_gpu_init(void);

/* Releases any GPU resources. */
void mlrt_gpu_shutdown(void);

/* Mines a batch of nonces on the GPU.
 *
 *   header:        96-byte serialized block header (nonce field is overwritten per-thread)
 *   target:        32-byte big-endian difficulty target
 *   start_nonce:   first nonce the kernel will try
 *   batch_size:    number of nonces to try in this call (must be a multiple of 256)
 *   out_nonce:     receives the winning nonce on success (unchanged on miss)
 *   out_found:     set to 1 if a valid nonce was found, 0 otherwise
 *
 * Returns 0 on kernel success (regardless of whether a nonce was found),
 * negative on CUDA error. */
int mlrt_gpu_mine(
    const uint8_t* header,
    const uint8_t* target,
    uint64_t       start_nonce,
    uint64_t       batch_size,
    uint64_t*      out_nonce,
    int*           out_found);

/* Host-side SHA3-256 reference implementation used by the self-test.
 * Computes DoubleSHA3256(input) using CPU code that matches the GPU kernel. */
void mlrt_cpu_hash(const uint8_t* input, uint32_t len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* MLRT_GPU_H */
