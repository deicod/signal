package sesame

import (
	"errors"
	"testing"
	"time"

	signalerrors "github.com/deicod/signal/errors"
	"github.com/deicod/signal/keys"
	"github.com/deicod/signal/session"
	"github.com/deicod/signal/store"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

func TestStateSerializeDeterministic(t *testing.T) {
	s := NewState()
	u := s.getOrCreateUser("bob")
	u.devices[2] = &deviceRecord{stale: true, staleSince: time.Unix(10, 0).UTC()}
	u.devices[1] = &deviceRecord{}
	s.getOrCreateUser("alice").stale = true

	one, err := s.Serialize()
	require.NoError(t, err)

	decoded, err := DeserializeState(one)
	require.NoError(t, err)

	two, err := decoded.Serialize()
	require.NoError(t, err)

	require.Equal(t, one, two)
}

func TestManagerApplyDeviceListMarksStale(t *testing.T) {
	localID, _ := keys.GenerateIdentityKeyPair()
	st := memory.NewStore(localID, 1)

	m := NewManager(st, store.Address{Name: "me", Device: 1}, time.Minute)
	now := time.Unix(100, 0).UTC()

	require.NoError(t, m.ApplyDeviceList("bob", []Device{{DeviceID: 1}, {DeviceID: 2}}, now))
	addrs, err := m.NonStaleDevices("bob")
	require.NoError(t, err)
	require.Equal(t, []store.Address{{Name: "bob", Device: 1}, {Name: "bob", Device: 2}}, addrs)

	require.NoError(t, m.ApplyDeviceList("bob", []Device{{DeviceID: 2}}, now.Add(time.Second)))
	addrs, err = m.NonStaleDevices("bob")
	require.NoError(t, err)
	require.Equal(t, []store.Address{{Name: "bob", Device: 2}}, addrs)

	state, err := m.loadState()
	require.NoError(t, err)
	rec := state.user("bob")
	require.NotNil(t, rec)
	require.True(t, rec.devices[1].stale)
}

func TestManagerIdentityMismatchDeletesSessionAndReturnsUntrusted(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)

	bobID, _ := keys.GenerateIdentityKeyPair()
	bobStore := memory.NewStore(bobID, 2)

	signed, _ := keys.GenerateSignedPreKey(bobID, 1)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 2)
	require.NoError(t, bobStore.StoreSignedPreKey(signed.ID, signed))
	require.NoError(t, bobStore.StoreKyberPreKey(kyber.ID, kyber))
	reg, _ := bobStore.GetLocalRegistrationID()
	bundle, _ := keys.NewPreKeyBundleWithKyber(reg, 1, nil, signed, kyber, bobID.PublicKey)
	require.NoError(t, bundle.Validate())

	bobAddr := store.Address{Name: "bob", Device: 1}
	aliceToBob := session.NewCipher(aliceStore, bobAddr)
	_, err := aliceToBob.EncryptWithPreKeyBundle(bundle, []byte("hi"))
	require.NoError(t, err)
	require.True(t, aliceStore.ContainsSession(bobAddr))

	oldIdentity, _ := aliceStore.GetIdentity(bobAddr)
	require.NotNil(t, oldIdentity)

	newBobID, _ := keys.GenerateIdentityKeyPair()
	m := NewManager(aliceStore, store.Address{Name: "alice", Device: 1}, time.Minute)
	err = m.ApplyDeviceList("bob", []Device{{DeviceID: 1, IdentityKey: &newBobID.PublicKey}}, time.Unix(200, 0).UTC())
	require.Error(t, err)
	require.True(t, errors.Is(err, signalerrors.ErrUntrustedIdentity))
	require.False(t, aliceStore.ContainsSession(bobAddr))

	afterIdentity, _ := aliceStore.GetIdentity(bobAddr)
	require.Equal(t, oldIdentity, afterIdentity) // roster update does not auto-trust new identities
}

func TestManagerPruneStaleDeletesSessionsAndIdentities(t *testing.T) {
	aliceID, _ := keys.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)

	bobID, _ := keys.GenerateIdentityKeyPair()
	bobStore := memory.NewStore(bobID, 2)

	signed, _ := keys.GenerateSignedPreKey(bobID, 1)
	kyber, _ := keys.GenerateKyberPreKey(bobID, 2)
	require.NoError(t, bobStore.StoreSignedPreKey(signed.ID, signed))
	require.NoError(t, bobStore.StoreKyberPreKey(kyber.ID, kyber))
	reg, _ := bobStore.GetLocalRegistrationID()
	bundle, _ := keys.NewPreKeyBundleWithKyber(reg, 1, nil, signed, kyber, bobID.PublicKey)
	require.NoError(t, bundle.Validate())

	bobAddr := store.Address{Name: "bob", Device: 1}
	aliceToBob := session.NewCipher(aliceStore, bobAddr)
	_, err := aliceToBob.EncryptWithPreKeyBundle(bundle, []byte("hi"))
	require.NoError(t, err)
	require.True(t, aliceStore.ContainsSession(bobAddr))

	now := time.Unix(300, 0).UTC()
	m := NewManager(aliceStore, store.Address{Name: "alice", Device: 1}, 10*time.Second)
	require.NoError(t, m.ApplyDeviceList("bob", []Device{{DeviceID: 1}}, now))

	require.NoError(t, m.MarkDeviceStale(bobAddr, now))
	require.NoError(t, m.PruneStale(now.Add(11*time.Second)))

	require.False(t, aliceStore.ContainsSession(bobAddr))
	id, _ := aliceStore.GetIdentity(bobAddr)
	require.Nil(t, id)
}
