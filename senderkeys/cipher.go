package senderkeys

import (
	"fmt"

	signalcrypto "github.com/deicod/signal/crypto"
	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/store"
)

// Cipher provides Encrypt/Decrypt for Sender Key group messages for a (group, sender) tuple.
type Cipher struct {
	store store.SenderKeyStore
	name  store.SenderKeyName
}

// NewCipher constructs a sender key cipher for the given store and name.
func NewCipher(s store.SenderKeyStore, name store.SenderKeyName) *Cipher {
	return &Cipher{
		store: s,
		name:  name,
	}
}

// Encrypt encrypts plaintext using the current sender key state.
// A sender key state must already exist (typically created via Builder.Create/Rotate).
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil || c.store == nil {
		return nil, fmt.Errorf("sender key cipher not initialized")
	}

	record, err := c.loadRecord()
	if err != nil {
		return nil, err
	}
	if record.isEmpty() {
		return nil, fmt.Errorf("%w: no sender key for %v", signalerrors.ErrNoSenderKey, c.name)
	}

	st, err := record.current()
	if err != nil {
		return nil, fmt.Errorf("%w: no sender key for %v", signalerrors.ErrNoSenderKey, c.name)
	}
	if !st.hasPrivate {
		return nil, fmt.Errorf("%w: sender key state missing signing private key", signalerrors.ErrInvalidMessage)
	}

	chainKey := senderChainKey{iteration: st.chainIteration, seed: st.chainSeed}
	messageKey, err := chainKey.senderMessageKey()
	if err != nil {
		return nil, err
	}

	ciphertext, err := signalcrypto.AESCBCEncrypt(messageKey.cipherKey[:], messageKey.iv[:], plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: sender key encrypt: %v", signalerrors.ErrInvalidMessage, err)
	}

	msg := senderKeyMessage{
		messageVersion: st.messageVersion,
		distributionID: st.distributionID,
		keyID:          st.keyID,
		iteration:      messageKey.iteration,
		ciphertext:     ciphertext,
	}
	signBytes := msg.signedBytes()

	sig, err := signalcrypto.XEdDSASign(st.signingPrivateSeed, signBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: sender key sign: %v", signalerrors.ErrInvalidMessage, err)
	}
	if len(sig) != senderKeySignatureSize {
		return nil, fmt.Errorf("%w: sender key signature length", signalerrors.ErrInvalidMessage)
	}
	copy(msg.signature[:], sig)

	next, err := chainKey.next()
	if err != nil {
		return nil, err
	}
	st.chainIteration = next.iteration
	st.chainSeed = next.seed

	if err := c.persistRecord(record); err != nil {
		return nil, err
	}
	return msg.serialize(), nil
}

// Decrypt decrypts a sender key group message, updating the sender key state on success.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if c == nil || c.store == nil {
		return nil, fmt.Errorf("sender key cipher not initialized")
	}

	msg, signedBytes, err := parseSenderKeyMessage(ciphertext)
	if err != nil {
		return nil, err
	}

	record, err := c.loadRecord()
	if err != nil {
		return nil, err
	}
	if record.isEmpty() {
		return nil, fmt.Errorf("%w: no sender key for %v", signalerrors.ErrNoSenderKey, c.name)
	}

	st, err := record.state(msg.distributionID, msg.keyID)
	if err != nil {
		return nil, fmt.Errorf("%w: no sender key for %v", signalerrors.ErrNoSenderKey, c.name)
	}

	if msg.messageVersion != st.messageVersion {
		return nil, fmt.Errorf("%w: sender key message version %d", signalerrors.ErrInvalidMessage, msg.messageVersion)
	}

	if !signalcrypto.XEdDSAVerify(st.signingPublic, msg.signature[:], signedBytes) {
		return nil, signalerrors.ErrInvalidSignature
	}

	messageKey, err := getSenderMessageKey(st, msg.iteration)
	if err != nil {
		return nil, err
	}

	plaintext, err := signalcrypto.AESCBCDecrypt(messageKey.cipherKey[:], messageKey.iv[:], msg.ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: sender key decrypt: %v", signalerrors.ErrInvalidMessage, err)
	}

	if err := c.persistRecord(record); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func getSenderMessageKey(st *state, iteration uint32) (senderMessageKey, error) {
	if st == nil {
		return senderMessageKey{}, fmt.Errorf("%w: missing sender key state", signalerrors.ErrInvalidMessage)
	}

	chainKey := senderChainKey{iteration: st.chainIteration, seed: st.chainSeed}

	if chainKey.iteration > iteration {
		seed, ok := st.removeMessageKey(iteration)
		if !ok {
			return senderMessageKey{}, signalerrors.ErrDuplicateMessage
		}
		return newSenderMessageKey(iteration, seed)
	}

	if iteration-chainKey.iteration > maxMessageKeysPerState {
		return senderMessageKey{}, signalerrors.ErrMaxSkipExceeded
	}

	for chainKey.iteration < iteration {
		mk, err := chainKey.senderMessageKey()
		if err != nil {
			return senderMessageKey{}, err
		}
		st.addMessageKey(messageKey{iteration: chainKey.iteration, seed: mk.seed})
		chainKey, err = chainKey.next()
		if err != nil {
			return senderMessageKey{}, err
		}
	}

	next, err := chainKey.next()
	if err != nil {
		return senderMessageKey{}, err
	}
	st.chainIteration = next.iteration
	st.chainSeed = next.seed

	return chainKey.senderMessageKey()
}

func (c *Cipher) loadRecord() (*Record, error) {
	rec, err := c.store.LoadSenderKey(c.name)
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

func (c *Cipher) persistRecord(record *Record) error {
	if record == nil {
		return fmt.Errorf("%w: sender key record is nil", signalerrors.ErrInvalidMessage)
	}
	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("%w: serialize sender key record: %v", signalerrors.ErrInvalidMessage, err)
	}
	if err := c.store.StoreSenderKey(c.name, &store.SenderKeyRecord{Data: data}); err != nil {
		return fmt.Errorf("store sender key record: %w", err)
	}
	return nil
}
