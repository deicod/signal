package crypto

import "runtime"

// ZeroBytes overwrites b with zeros and keeps it alive until the overwrite completes.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroKey overwrites k with zeros and keeps it alive until the overwrite completes.
func ZeroKey(k *[32]byte) {
	if k == nil {
		return
	}
	for i := range k {
		k[i] = 0
	}
	runtime.KeepAlive(k)
}
