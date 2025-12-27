package memory

import (
	"testing"

	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/store"
	"github.com/stretchr/testify/require"
)

func TestMemoryStoreIdentity(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	ms := NewStore(id, 1234)

	gotID, err := ms.GetIdentityKeyPair()
	require.NoError(t, err)
	require.Equal(t, id, gotID)

	reg, err := ms.GetLocalRegistrationID()
	require.NoError(t, err)
	require.Equal(t, uint32(1234), reg)

	addr := store.Address{Name: "alice", Device: 1}
	require.True(t, ms.IsTrustedIdentity(addr, &id.PublicKey, store.DirectionSending))

	require.NoError(t, ms.SaveIdentity(addr, &id.PublicKey))
	require.True(t, ms.IsTrustedIdentity(addr, &id.PublicKey, store.DirectionSending))
}

func TestMemoryStorePreKeys(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	ms := NewStore(id, 1)

	pk, _ := keys.GeneratePreKey(5)
	require.NoError(t, ms.StorePreKey(pk.ID, pk))
	require.True(t, ms.ContainsPreKey(pk.ID))

	loaded, err := ms.LoadPreKey(pk.ID)
	require.NoError(t, err)
	require.Equal(t, pk, loaded)

	require.NoError(t, ms.RemovePreKey(pk.ID))
	require.False(t, ms.ContainsPreKey(pk.ID))
}

func TestMemoryStoreSignedPreKeys(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	ms := NewStore(id, 1)

	spk, _ := keys.GenerateSignedPreKey(id, 7)
	require.NoError(t, ms.StoreSignedPreKey(spk.ID, spk))
	require.True(t, ms.ContainsSignedPreKey(spk.ID))

	loaded, err := ms.LoadSignedPreKey(spk.ID)
	require.NoError(t, err)
	require.Equal(t, spk, loaded)

	require.NoError(t, ms.RemoveSignedPreKey(spk.ID))
	require.False(t, ms.ContainsSignedPreKey(spk.ID))
}

func TestMemoryStoreKyberPreKeys(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	ms := NewStore(id, 1)

	kpk, _ := keys.GenerateKyberPreKey(id, 9)
	require.NoError(t, ms.StoreKyberPreKey(kpk.ID, kpk))
	require.True(t, ms.ContainsKyberPreKey(kpk.ID))

	loaded, err := ms.LoadKyberPreKey(kpk.ID)
	require.NoError(t, err)
	require.Equal(t, kpk, loaded)

	require.NoError(t, ms.RemoveKyberPreKey(kpk.ID))
	require.False(t, ms.ContainsKyberPreKey(kpk.ID))
}

func TestMemoryStoreSessions(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	ms := NewStore(id, 1)

	addr1 := store.Address{Name: "alice", Device: 1}
	addr2 := store.Address{Name: "alice", Device: 2}

	data := []byte("session-record")
	rec := &store.SessionRecord{Data: data}
	require.NoError(t, ms.StoreSession(addr1, rec))
	require.True(t, ms.ContainsSession(addr1))

	loaded, err := ms.LoadSession(addr1)
	require.NoError(t, err)
	require.Equal(t, rec, loaded)

	data[0] ^= 0xff
	loaded2, err := ms.LoadSession(addr1)
	require.NoError(t, err)
	require.NotEqual(t, rec, loaded2) // stored value is cloned on write

	require.NoError(t, ms.DeleteSession(addr1))
	require.False(t, ms.ContainsSession(addr1))

	require.NoError(t, ms.StoreSession(addr1, rec))
	require.NoError(t, ms.StoreSession(addr2, rec))
	require.NoError(t, ms.DeleteAllSessions("alice"))
	require.False(t, ms.ContainsSession(addr1))
	require.False(t, ms.ContainsSession(addr2))
}

func TestMemoryStoreSenderKeys(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	ms := NewStore(id, 1)

	name := store.SenderKeyName{
		Group:  "group-1",
		Sender: store.Address{Name: "alice", Device: 1},
	}

	data := []byte("sender-key-record")
	rec := &store.SenderKeyRecord{Data: data}

	require.NoError(t, ms.StoreSenderKey(name, rec))
	require.True(t, ms.ContainsSenderKey(name))

	loaded, err := ms.LoadSenderKey(name)
	require.NoError(t, err)
	require.Equal(t, rec, loaded)

	data[0] ^= 0xff
	loaded2, err := ms.LoadSenderKey(name)
	require.NoError(t, err)
	require.NotEqual(t, rec, loaded2) // stored value is cloned on write

	require.NoError(t, ms.DeleteSenderKey(name))
	require.False(t, ms.ContainsSenderKey(name))

	name2 := store.SenderKeyName{
		Group:  "group-1",
		Sender: store.Address{Name: "bob", Device: 1},
	}
	name3 := store.SenderKeyName{
		Group:  "group-2",
		Sender: store.Address{Name: "bob", Device: 1},
	}
	require.NoError(t, ms.StoreSenderKey(name, rec))
	require.NoError(t, ms.StoreSenderKey(name2, rec))
	require.NoError(t, ms.StoreSenderKey(name3, rec))
	require.NoError(t, ms.DeleteAllSenderKeys("group-1"))
	require.False(t, ms.ContainsSenderKey(name))
	require.False(t, ms.ContainsSenderKey(name2))
	require.True(t, ms.ContainsSenderKey(name3))
}

func TestMemoryStoreSesameState(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	ms := NewStore(id, 1)

	rec, err := ms.LoadSesameState()
	require.NoError(t, err)
	require.Nil(t, rec)

	data := []byte("sesame")
	require.NoError(t, ms.StoreSesameState(&store.SesameRecord{Data: data}))

	loaded, err := ms.LoadSesameState()
	require.NoError(t, err)
	require.Equal(t, &store.SesameRecord{Data: data}, loaded)

	data[0] ^= 0xff
	loaded2, err := ms.LoadSesameState()
	require.NoError(t, err)
	require.NotEqual(t, &store.SesameRecord{Data: data}, loaded2) // stored value is cloned on write

	require.NoError(t, ms.DeleteSesameState())
	loaded, err = ms.LoadSesameState()
	require.NoError(t, err)
	require.Nil(t, loaded)
}
