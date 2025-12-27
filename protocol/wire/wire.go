package wire

const (
	ciphertextMessageCurrentVersion  uint8 = 4
	ciphertextMessagePreKyberVersion uint8 = 3
	senderKeyMessageCurrentVersion   uint8 = 3

	signalMessageMACLength = 8
)

func versionByte(messageVersion, currentVersion uint8) byte {
	return byte(((messageVersion & 0x0f) << 4) | (currentVersion & 0x0f))
}

func parseMessageVersion(b byte) uint8 {
	return b >> 4
}
