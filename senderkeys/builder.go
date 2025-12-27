package senderkeys

import (
	"fmt"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/store"
)

// Builder constructs Sender Key sessions for a (group, sender) tuple.
type Builder struct {
	store store.SenderKeyStore
	name  store.SenderKeyName
}

// NewBuilder constructs a sender key builder for the given store and name.
func NewBuilder(s store.SenderKeyStore, name store.SenderKeyName) *Builder {
	return &Builder{
		store: s,
		name:  name,
	}
}

// Create returns a distribution message for the current sender key state, creating one if absent.
// The resulting message is typically encrypted and delivered individually to every group member.
func (b *Builder) Create() ([]byte, error) {
	if b == nil || b.store == nil {
		return nil, fmt.Errorf("sender key builder not initialized")
	}

	record, err := b.loadRecord()
	if err != nil {
		return nil, err
	}

	if record.isEmpty() {
		state, err := newSendingState()
		if err != nil {
			return nil, err
		}
		if err := record.setState(state); err != nil {
			return nil, err
		}
		if err := b.persistRecord(record); err != nil {
			return nil, err
		}
	}

	cur, err := record.current()
	if err != nil {
		return nil, err
	}
	if !cur.hasPrivate {
		return nil, fmt.Errorf("%w: sender key state missing signing private key", signalerrors.ErrInvalidMessage)
	}

	msg := distributionMessage{
		messageVersion: cur.messageVersion,
		distributionID: cur.distributionID,
		keyID:          cur.keyID,
		iteration:      cur.chainIteration,
		chainKey:       cur.chainSeed,
		signingPublic:  cur.signingPublic,
	}
	return msg.serialize(), nil
}

// Rotate generates a new sender key state and returns the distribution message for it.
// Existing states are retained (up to the record's max state limit) so older messages can still be decrypted.
func (b *Builder) Rotate() ([]byte, error) {
	if b == nil || b.store == nil {
		return nil, fmt.Errorf("sender key builder not initialized")
	}

	record, err := b.loadRecord()
	if err != nil {
		return nil, err
	}

	state, err := newSendingState()
	if err != nil {
		return nil, err
	}
	if err := record.setState(state); err != nil {
		return nil, err
	}
	if err := b.persistRecord(record); err != nil {
		return nil, err
	}

	msg := distributionMessage{
		messageVersion: state.messageVersion,
		distributionID: state.distributionID,
		keyID:          state.keyID,
		iteration:      state.chainIteration,
		chainKey:       state.chainSeed,
		signingPublic:  state.signingPublic,
	}
	return msg.serialize(), nil
}

// Process updates the sender key record using a received distribution message.
func (b *Builder) Process(distribution []byte) error {
	if b == nil || b.store == nil {
		return fmt.Errorf("sender key builder not initialized")
	}
	msg, err := parseDistributionMessage(distribution)
	if err != nil {
		return err
	}

	record, err := b.loadRecord()
	if err != nil {
		return err
	}

	state := &state{
		messageVersion: msg.messageVersion,
		distributionID: msg.distributionID,
		keyID:          msg.keyID,
		chainIteration: msg.iteration,
		chainSeed:      msg.chainKey,
		signingPublic:  msg.signingPublic,
		hasPrivate:     false,
	}
	if err := record.setState(state); err != nil {
		return err
	}
	return b.persistRecord(record)
}

func (b *Builder) loadRecord() (*Record, error) {
	rec, err := b.store.LoadSenderKey(b.name)
	if err != nil {
		return nil, fmt.Errorf("load sender key record: %w", err)
	}
	if rec == nil || len(rec.Data) == 0 {
		return NewRecord(0), nil
	}
	record, err := DeserializeRecord(rec.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: deserialize sender key record: %v", signalerrors.ErrInvalidMessage, err)
	}
	if record.maxStates <= 0 {
		record.maxStates = DefaultMaxStates
	}
	return record, nil
}

func (b *Builder) persistRecord(record *Record) error {
	if record == nil {
		return fmt.Errorf("%w: sender key record is nil", signalerrors.ErrInvalidMessage)
	}
	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("%w: serialize sender key record: %v", signalerrors.ErrInvalidMessage, err)
	}
	return b.store.StoreSenderKey(b.name, &store.SenderKeyRecord{Data: data})
}

func newSendingState() (*state, error) {
	keyID, err := generateSenderKeyID()
	if err != nil {
		return nil, fmt.Errorf("generate sender key id: %w", err)
	}
	distributionID, err := generateDistributionID()
	if err != nil {
		return nil, fmt.Errorf("generate sender key distribution id: %w", err)
	}
	seed, err := generateSenderKeySeed()
	if err != nil {
		return nil, fmt.Errorf("generate sender chain key: %w", err)
	}
	pub, priv, err := generateSigningKey()
	if err != nil {
		return nil, fmt.Errorf("generate sender signing key: %w", err)
	}
	return &state{
		messageVersion:     senderKeyMessageVersion,
		distributionID:     distributionID,
		keyID:              keyID,
		chainIteration:     0,
		chainSeed:          seed,
		signingPublic:      pub,
		signingPrivateSeed: priv,
		hasPrivate:         true,
	}, nil
}
