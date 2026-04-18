// Reference hashes: run this to see the expected output of the CUDA selftest.
//
//	go run ./internal/mining/cuda/reference
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/malairt/malairt/internal/crypto"
)

func main() {
	show := func(tag string, input []byte) {
		h := crypto.DoubleSHA3256(input)
		fmt.Printf("%s %s\n", tag, hex.EncodeToString(h[:]))
	}

	show(`DoubleSHA3256("")    =`, []byte(""))
	show(`DoubleSHA3256("abc") =`, []byte("abc"))

	zeros := make([]byte, 96)
	show(`DoubleSHA3256(zeros96)=`, zeros)
}
