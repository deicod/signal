package senderkeys

import (
	"errors"
	"testing"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestSenderKeysRoundTrip(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)
	bobStore := memory.NewStore(bobID, 2)

	name := store.SenderKeyName{
		Group:  "group-1",
		Sender: store.Address{Name: "alice", Device: 1},
	}

	dist, err := NewBuilder(aliceStore, name).Create()
	require.NoError(t, err)
	require.NoError(t, NewBuilder(bobStore, name).Process(dist))

	aliceCipher := NewCipher(aliceStore, name)
	bobCipher := NewCipher(bobStore, name)

	ct, err := aliceCipher.Encrypt([]byte("hi"))
	require.NoError(t, err)

	pt, err := bobCipher.Decrypt(ct)
	require.NoError(t, err)
	require.Equal(t, []byte("hi"), pt)
}

func TestSenderKeysOutOfOrderAndDuplicate(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)
	bobStore := memory.NewStore(bobID, 2)

	name := store.SenderKeyName{
		Group:  "group-1",
		Sender: store.Address{Name: "alice", Device: 1},
	}

	dist, err := NewBuilder(aliceStore, name).Create()
	require.NoError(t, err)
	require.NoError(t, NewBuilder(bobStore, name).Process(dist))

	aliceCipher := NewCipher(aliceStore, name)
	bobCipher := NewCipher(bobStore, name)

	msg1, err := aliceCipher.Encrypt([]byte("m1"))
	require.NoError(t, err)
	msg2, err := aliceCipher.Encrypt([]byte("m2"))
	require.NoError(t, err)

	pt, err := bobCipher.Decrypt(msg2)
	require.NoError(t, err)
	require.Equal(t, []byte("m2"), pt)

	pt, err = bobCipher.Decrypt(msg1)
	require.NoError(t, err)
	require.Equal(t, []byte("m1"), pt)

	_, err = bobCipher.Decrypt(msg1)
	require.Error(t, err)
	require.True(t, errors.Is(err, signalerrors.ErrDuplicateMessage))
}

func TestSenderKeysRotation(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)
	bobStore := memory.NewStore(bobID, 2)

	name := store.SenderKeyName{
		Group:  "group-1",
		Sender: store.Address{Name: "alice", Device: 1},
	}

	aliceBuilder := NewBuilder(aliceStore, name)
	dist1, err := aliceBuilder.Create()
	require.NoError(t, err)

	bobBuilder := NewBuilder(bobStore, name)
	require.NoError(t, bobBuilder.Process(dist1))

	aliceCipher := NewCipher(aliceStore, name)
	bobCipher := NewCipher(bobStore, name)

	oldMsg, err := aliceCipher.Encrypt([]byte("old"))
	require.NoError(t, err)

	dist2, err := aliceBuilder.Rotate()
	require.NoError(t, err)

	newMsg, err := aliceCipher.Encrypt([]byte("new"))
	require.NoError(t, err)

	_, err = bobCipher.Decrypt(newMsg)
	require.Error(t, err)
	require.True(t, errors.Is(err, signalerrors.ErrNoSenderKey))

	require.NoError(t, bobBuilder.Process(dist2))

	pt, err := bobCipher.Decrypt(oldMsg)
	require.NoError(t, err)
	require.Equal(t, []byte("old"), pt)

	pt, err = bobCipher.Decrypt(newMsg)
	require.NoError(t, err)
	require.Equal(t, []byte("new"), pt)
}

func TestSenderKeyDistributionPersistsFields(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)

	name := store.SenderKeyName{
		Group:  "group-1",
		Sender: store.Address{Name: "alice", Device: 1},
	}

	dist, err := NewBuilder(aliceStore, name).Create()
	require.NoError(t, err)

	parsed, err := parseDistributionMessage(dist)
	require.NoError(t, err)
	require.Equal(t, senderKeyMessageVersion, parsed.messageVersion)
	require.Equal(t, uint32(0), parsed.iteration)

	rec, err := aliceStore.LoadSenderKey(name)
	require.NoError(t, err)
	require.NotNil(t, rec)

	record, err := DeserializeRecord(rec.Data)
	require.NoError(t, err)
	state, err := record.current()
	require.NoError(t, err)

	require.Equal(t, parsed.distributionID, state.distributionID)
	require.Equal(t, parsed.keyID, state.keyID)
	require.Equal(t, parsed.iteration, state.chainIteration)
	require.Equal(t, parsed.messageVersion, state.messageVersion)
}

func TestSenderKeyTamperSignatureRejected(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	bobID, _ := keys.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)
	bobStore := memory.NewStore(bobID, 2)

	name := store.SenderKeyName{
		Group:  "group-1",
		Sender: store.Address{Name: "alice", Device: 1},
	}

	dist, err := NewBuilder(aliceStore, name).Create()
	require.NoError(t, err)
	require.NoError(t, NewBuilder(bobStore, name).Process(dist))

	aliceCipher := NewCipher(aliceStore, name)
	bobCipher := NewCipher(bobStore, name)

	ct, err := aliceCipher.Encrypt([]byte("hi"))
	require.NoError(t, err)

	msg, _, err := parseSenderKeyMessage(ct)
	require.NoError(t, err)
	require.NotEmpty(t, msg.ciphertext)
	msg.ciphertext[0] ^= 0xFF

	_, err = bobCipher.Decrypt(msg.serialize())
	require.ErrorIs(t, err, signalerrors.ErrInvalidSignature)
}

func TestSenderKeyChainIDIs31Bit(t *testing.T) {
	for i := 0; i < 100; i++ {
		id, err := generateSenderKeyID()
		require.NoError(t, err)
		require.Zero(t, id&0x80000000)
	}
}

func TestSenderKeysMaxSkipExceeded(t *testing.T) {
	st := &state{}
	_, err := getSenderMessageKey(st, maxMessageKeysPerState+1)
	require.ErrorIs(t, err, signalerrors.ErrMaxSkipExceeded)
}

func TestSenderKeyRecordSerializeDeterministic(t *testing.T) {
	rec := NewRecord(3)

	st := &state{
		messageVersion: senderKeyMessageVersion,
		distributionID: [distributionIDSize]byte{1, 2, 3, 4},
		keyID:          1,
		chainIteration: 9,
		hasPrivate:     true,
	}
	st.addMessageKey(messageKey{iteration: 4})
	st.addMessageKey(messageKey{iteration: 5})

	require.NoError(t, rec.setState(st))

	one, err := rec.Serialize()
	require.NoError(t, err)

	decoded, err := DeserializeRecord(one)
	require.NoError(t, err)

	two, err := decoded.Serialize()
	require.NoError(t, err)
	require.Equal(t, one, two)
}
