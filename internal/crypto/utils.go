package crypto

// ZeroBytes overwrites all bytes in b with zeros to remove sensitive data
// (e.g. DEK plaintext) from memory after use.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
