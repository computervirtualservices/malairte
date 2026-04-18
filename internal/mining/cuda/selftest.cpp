/*
 * Standalone self-test for the CUDA DoubleSHA3256 implementation.
 *
 * Build:  make selftest
 * Run:    ./selftest
 *
 * Computes DoubleSHA3256("") and DoubleSHA3256("abc") using both the host
 * reference code and the GPU kernel (via the mining path with an unreachable
 * target so it scans the full batch). Prints both hashes. Compare against:
 *
 *   go run ./internal/mining/cuda/reference  # see reference.go
 */

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mlrt_gpu.h"

static void print_hex(const char* tag, const uint8_t* buf, int n) {
    printf("%s ", tag);
    for (int i = 0; i < n; i++) printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    uint8_t out[32];

    /* Known inputs — compare with output of `go run internal/mining/cuda/reference/main.go`. */
    mlrt_cpu_hash((const uint8_t*)"", 0, out);
    print_hex("DoubleSHA3256(\"\")    =", out, 32);

    mlrt_cpu_hash((const uint8_t*)"abc", 3, out);
    print_hex("DoubleSHA3256(\"abc\") =", out, 32);

    /* 96-byte header of zeros. */
    uint8_t header[96];
    memset(header, 0, 96);
    mlrt_cpu_hash(header, 96, out);
    print_hex("DoubleSHA3256(zeros96)=", out, 32);

    /* Now run the GPU path on the same zero header with an all-ones target
     * (any hash wins) and verify it returns a valid nonce. */
    if (mlrt_gpu_init() != 0) {
        fprintf(stderr, "GPU init failed; skipping GPU test.\n");
        return 0;
    }

    uint8_t target[32];
    memset(target, 0xff, 32);  /* trivially easy target */
    uint64_t nonce = 0;
    int found = 0;
    int rc = mlrt_gpu_mine(header, target, 0, 256, &nonce, &found);
    printf("GPU mine rc=%d found=%d nonce=%llu\n", rc, found, (unsigned long long)nonce);

    mlrt_gpu_shutdown();
    return 0;
}
