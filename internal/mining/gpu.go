//go:build !cuda

package mining

import "log"

// gpuLoop is a no-op when the binary is built without `-tags cuda`.
// Users who want GPU mining must install CUDA Toolkit and rebuild:
//
//	cd internal/mining/cuda && make
//	go build -tags cuda ./cmd/malairted
func (m *CpuMiner) gpuLoop() {
	log.Printf("[miner] --gpu set but this build has no CUDA support — staying CPU-only")
	log.Printf("[miner] to enable: cd internal/mining/cuda && make; then: go build -tags cuda ./cmd/malairted")
}
