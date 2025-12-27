package wire

const (
	CiphertextMessageCurrentVersion  uint8 = 4
	CiphertextMessagePreKyberVersion uint8 = 3
	SenderKeyMessageCurrentVersion   uint8 = 3

	SignalMessageMACLength = 8
)

func versionByte(messageVersion, currentVersion uint8) byte {
	return byte(((messageVersion & 0x0f) << 4) | (currentVersion & 0x0f))
}

func parseMessageVersion(b byte) uint8 {
	return b >> 4
}
