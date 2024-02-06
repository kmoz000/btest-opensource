package main

import (
	"fmt"
	"testing"
)

func TestHelloEmpty(t *testing.T) {
	seq := uint64(1)
	bytes := genPacket(seq, 1500)
	fmt.Printf("bytes: %v (%d)", bytes[0:8], len(bytes))
}
