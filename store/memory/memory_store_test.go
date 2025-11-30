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

func TestMemoryStoreSessions(t *testing.T) {
	id, _ := keys.GenerateIdentityKeyPair()
	ms := NewStore(id, 1)

	addr1 := store.Address{Name: "alice", Device: 1}
	addr2 := store.Address{Name: "alice", Device: 2}

	rec := &store.SessionRecord{}
	require.NoError(t, ms.StoreSession(addr1, rec))
	require.True(t, ms.ContainsSession(addr1))

	loaded, err := ms.LoadSession(addr1)
	require.NoError(t, err)
	require.Equal(t, rec, loaded)

	require.NoError(t, ms.DeleteSession(addr1))
	require.False(t, ms.ContainsSession(addr1))

	require.NoError(t, ms.StoreSession(addr1, rec))
	require.NoError(t, ms.StoreSession(addr2, rec))
	require.NoError(t, ms.DeleteAllSessions("alice"))
	require.False(t, ms.ContainsSession(addr1))
	require.False(t, ms.ContainsSession(addr2))
}
