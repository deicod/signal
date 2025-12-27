package session

import (
	"fmt"
	"time"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/ratchet"
	"github.com/deicod/signal/store"
	"github.com/deicod/signal/x3dh"
)

// Builder bootstraps sessions using pre-key bundles and initial messages.
type Builder struct {
	store         store.ProtocolStore
	remoteAddress store.Address
}

// NewBuilder constructs a session builder for the given remote address.
func NewBuilder(s store.ProtocolStore, addr store.Address) *Builder {
	return &Builder{
		store:         s,
		remoteAddress: addr,
	}
}

// ProcessPreKeyBundle creates an outgoing session using the recipient's pre-key bundle.
// It returns the initialized Session and the X3DH initial message to send.
func (b *Builder) ProcessPreKeyBundle(bundle *keys.PreKeyBundle) (*Session, *x3dh.Message, error) {
	if b == nil || b.store == nil {
		return nil, nil, fmt.Errorf("session builder not initialized")
	}
	if bundle == nil {
		return nil, nil, fmt.Errorf("pre-key bundle is nil")
	}

	localID, err := b.store.GetIdentityKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("load local identity: %w", err)
	}

	if !b.store.IsTrustedIdentity(b.remoteAddress, &bundle.IdentityKey, store.DirectionSending) {
		return nil, nil, fmt.Errorf("%w: %v", signalerrors.ErrUntrustedIdentity, b.remoteAddress)
	}

	initiator := x3dh.NewInitiator(localID)
	result, err := initiator.ProcessPreKeyBundle(bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh initiator: %w", err)
	}

	state, err := ratchet.InitializeState(result, true)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet init: %w", err)
	}

	session, err := NewSession(state, &localID.PublicKey, &bundle.IdentityKey, result.AssociatedData)
	if err != nil {
		return nil, nil, err
	}
	setSessionCiphertextVersion(session, ciphertextVersionFromX3DH(&result.InitialMessage))

	if err := b.store.SaveIdentity(b.remoteAddress, &bundle.IdentityKey); err != nil {
		return nil, nil, fmt.Errorf("save identity: %w", err)
	}
	return session, &result.InitialMessage, nil
}

// ProcessPreKeyMessage handles an incoming X3DH initial message from a remote party and
// initializes the responder's session. It returns the Session and associated data.
func (b *Builder) ProcessPreKeyMessage(msg *x3dh.Message) (*Session, []byte, error) {
	if b == nil || b.store == nil {
		return nil, nil, fmt.Errorf("session builder not initialized")
	}
	if msg == nil {
		return nil, nil, fmt.Errorf("pre-key message is nil")
	}

	identityKey, err := b.store.GetIdentityKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("load local identity: %w", err)
	}

	if !b.store.IsTrustedIdentity(b.remoteAddress, &msg.IdentityKey, store.DirectionReceiving) {
		return nil, nil, fmt.Errorf("%w: %v", signalerrors.ErrUntrustedIdentity, b.remoteAddress)
	}

	signedPreKey, err := b.store.LoadSignedPreKey(msg.SignedPreKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("load signed pre-key: %w", err)
	}
	if signedPreKey == nil {
		return nil, nil, fmt.Errorf("%w: signed pre-key %d", signalerrors.ErrPreKeyNotFound, msg.SignedPreKeyID)
	}
	if b.store.SignedPreKeyExpired(signedPreKey, time.Now().UTC()) {
		return nil, nil, fmt.Errorf("%w: signed pre-key %d", signalerrors.ErrPreKeyExpired, msg.SignedPreKeyID)
	}

	responder := x3dh.NewResponder(identityKey, signedPreKey, b.store, b.store)
	result, err := responder.ProcessInitialMessage(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh responder: %w", err)
	}

	state, err := ratchet.InitializeState(result, false)
	if err != nil {
		return nil, nil, fmt.Errorf("ratchet init: %w", err)
	}

	session, err := NewSession(state, &identityKey.PublicKey, &msg.IdentityKey, result.AssociatedData)
	if err != nil {
		return nil, nil, err
	}
	setSessionCiphertextVersion(session, ciphertextVersionFromX3DH(msg))

	if err := b.store.SaveIdentity(b.remoteAddress, &msg.IdentityKey); err != nil {
		return nil, nil, fmt.Errorf("save identity: %w", err)
	}
	return session, result.AssociatedData, nil
}
