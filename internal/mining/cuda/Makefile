# Builds libmlrtgpu.a for CGO linkage.
#
# Requires NVIDIA CUDA Toolkit. Tested with CUDA 12.x/13.x.
#
# Override NVCC / CUDA_ARCH for your hardware:
#   make CUDA_ARCH=sm_90        # Hopper / RTX 5090 uses sm_120 in CUDA 13,
#                               # but sm_90 works on 12.x. See README.

NVCC      ?= nvcc

# Fat binary: native SASS for common cards + forward-compatible PTX so
# newer GPUs (Blackwell / sm_120) JIT from the highest PTX we emit.
# Override GENCODE to target a single arch for smaller, faster builds.
GENCODE ?= \
    -gencode=arch=compute_75,code=sm_75 \
    -gencode=arch=compute_86,code=sm_86 \
    -gencode=arch=compute_89,code=sm_89 \
    -gencode=arch=compute_90,code=sm_90 \
    -gencode=arch=compute_90,code=compute_90

NVCCFLAGS := -O3 $(GENCODE) -Xcompiler -fPIC --use_fast_math --std=c++17

LIB := libmlrtgpu.a
OBJ := mlrt_gpu.o

all: $(LIB)

$(LIB): $(OBJ)
	ar rcs $@ $^

$(OBJ): mlrt_gpu.cu mlrt_gpu.h
	$(NVCC) $(NVCCFLAGS) -c mlrt_gpu.cu -o $@

selftest: selftest.cpp $(LIB)
	$(NVCC) -O3 $(GENCODE) selftest.cpp $(LIB) -o selftest -lcudart
	./selftest

clean:
	rm -f $(OBJ) $(LIB) selftest

.PHONY: all clean selftest
