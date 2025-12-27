package wire

const (
	// CiphertextMessageCurrentVersion is the current 1:1 ciphertext wire version.
	CiphertextMessageCurrentVersion uint8 = 4
	// CiphertextMessagePreKyberVersion is the minimum version before Kyber support.
	CiphertextMessagePreKyberVersion uint8 = 3
	// SenderKeyMessageCurrentVersion is the current group message wire version.
	SenderKeyMessageCurrentVersion uint8 = 3

	// SignalMessageMACLength is the size of the Signal message MAC suffix.
	SignalMessageMACLength = 8
)

func versionByte(messageVersion, currentVersion uint8) byte {
	return byte(((messageVersion & 0x0f) << 4) | (currentVersion & 0x0f))
}

func parseMessageVersion(b byte) uint8 {
	return b >> 4
}
