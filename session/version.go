package session

import (
	wire "github.com/deicod/signal/protocol/wire"
	"github.com/deicod/signal/x3dh"
)

func normalizeCiphertextVersion(version uint8) (uint8, bool) {
	if version >= wire.CiphertextMessagePreKyberVersion && version <= wire.CiphertextMessageCurrentVersion {
		return version, true
	}
	return 0, false
}

func setSessionCiphertextVersion(session *Session, version uint8) {
	if session == nil {
		return
	}
	if v, ok := normalizeCiphertextVersion(version); ok {
		session.version = v
	}
}

func ciphertextVersionForSession(session *Session) uint8 {
	if session == nil {
		return wire.CiphertextMessageCurrentVersion
	}
	if v, ok := normalizeCiphertextVersion(session.version); ok {
		return v
	}
	return wire.CiphertextMessageCurrentVersion
}

func ciphertextVersionFromX3DH(msg *x3dh.Message) uint8 {
	if msg != nil && (msg.KyberPreKeyID != nil || len(msg.KyberCiphertext) > 0) {
		return wire.CiphertextMessageCurrentVersion
	}
	return wire.CiphertextMessagePreKyberVersion
}
