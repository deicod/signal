package signal_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deicod/signal"
	"github.com/deicod/signal/store/memory"
	"github.com/stretchr/testify/require"
)

type staticRosterProvider struct {
	devices []signal.SesameDevice
	bundles map[signal.Address]*signal.PreKeyBundle
	errOnce map[signal.Address]bool
}

func (p *staticRosterProvider) DeviceList(_ context.Context, _ string) ([]signal.SesameDevice, error) {
	return p.devices, nil
}

func (p *staticRosterProvider) PreKeyBundle(_ context.Context, addr signal.Address) (*signal.PreKeyBundle, error) {
	if p.errOnce != nil && p.errOnce[addr] {
		p.errOnce[addr] = false
		return nil, signal.ErrRosterChanged
	}
	if p.bundles == nil {
		return nil, nil
	}
	return p.bundles[addr], nil
}

func TestSesameConversationEncryptWithRosterBootstrapsSessions(t *testing.T) {
	aliceID, _ := signal.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)
	aliceAddr := signal.Address{Name: "alice", Device: 1}

	bob1ID, _ := signal.GenerateIdentityKeyPair()
	bob1Store := memory.NewStore(bob1ID, 2)
	signed1, _ := signal.GenerateAndStoreSignedPreKey(bob1Store, 1)
	kyber1, _ := signal.GenerateAndStoreKyberPreKey(bob1Store, 2)
	bundle1, _ := signal.BuildPreKeyBundle(bob1Store, 1, nil, signed1.ID, &kyber1.ID)
	bob1Addr := signal.Address{Name: "bob", Device: 1}

	bob2ID, _ := signal.GenerateIdentityKeyPair()
	bob2Store := memory.NewStore(bob2ID, 3)
	signed2, _ := signal.GenerateAndStoreSignedPreKey(bob2Store, 1)
	kyber2, _ := signal.GenerateAndStoreKyberPreKey(bob2Store, 2)
	bundle2, _ := signal.BuildPreKeyBundle(bob2Store, 2, nil, signed2.ID, &kyber2.ID)
	bob2Addr := signal.Address{Name: "bob", Device: 2}

	provider := &staticRosterProvider{
		devices: []signal.SesameDevice{
			{DeviceID: 1, IdentityKey: &bundle1.IdentityKey},
			{DeviceID: 2, IdentityKey: &bundle2.IdentityKey},
		},
		bundles: map[signal.Address]*signal.PreKeyBundle{
			bob1Addr: bundle1,
			bob2Addr: bundle2,
		},
		errOnce: map[signal.Address]bool{bob2Addr: true},
	}

	conv := signal.NewSesameConversation(aliceStore, aliceAddr, time.Hour)
	out, err := conv.EncryptWithRoster(context.Background(), "bob", []byte("hello"), provider, time.Now())
	require.NoError(t, err)
	require.Len(t, out, 2)

	bob1Cipher := signal.NewCipher(bob1Store, aliceAddr)
	pt, err := bob1Cipher.Decrypt(out[bob1Addr])
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	bob2Cipher := signal.NewCipher(bob2Store, aliceAddr)
	pt, err = bob2Cipher.Decrypt(out[bob2Addr])
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)

	out2, err := conv.Encrypt("bob", []byte("again"), nil)
	require.NoError(t, err)
	require.Len(t, out2, 2)

	pt, err = bob1Cipher.Decrypt(out2[bob1Addr])
	require.NoError(t, err)
	require.Equal(t, []byte("again"), pt)

	pt, err = bob2Cipher.Decrypt(out2[bob2Addr])
	require.NoError(t, err)
	require.Equal(t, []byte("again"), pt)
}

func TestSesameConversationEncryptMissingBundle(t *testing.T) {
	aliceID, _ := signal.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)
	aliceAddr := signal.Address{Name: "alice", Device: 1}

	provider := &staticRosterProvider{
		devices: []signal.SesameDevice{
			{DeviceID: 1},
		},
	}

	conv := signal.NewSesameConversation(aliceStore, aliceAddr, time.Hour)
	_, err := conv.EncryptWithRoster(context.Background(), "bob", []byte("missing"), provider, time.Now())
	require.Error(t, err)

	var missing *signal.MissingBundleError
	require.ErrorAs(t, err, &missing)
	require.Len(t, missing.Addresses, 1)
	require.True(t, errors.Is(err, signal.ErrNoSession))
}

func TestSesameConversationDecryptTouchesRoster(t *testing.T) {
	aliceID, _ := signal.GenerateIdentityKeyPair()
	aliceStore := memory.NewStore(aliceID, 1)
	aliceAddr := signal.Address{Name: "alice", Device: 1}

	bobID, _ := signal.GenerateIdentityKeyPair()
	bobStore := memory.NewStore(bobID, 2)
	signed, _ := signal.GenerateAndStoreSignedPreKey(bobStore, 1)
	kyber, _ := signal.GenerateAndStoreKyberPreKey(bobStore, 2)
	bundle, _ := signal.BuildPreKeyBundle(bobStore, 1, nil, signed.ID, &kyber.ID)
	bobAddr := signal.Address{Name: "bob", Device: 1}

	aliceCipher := signal.NewCipher(aliceStore, bobAddr)
	initMsg, err := aliceCipher.EncryptWithPreKeyBundle(bundle, []byte("init"))
	require.NoError(t, err)

	bobCipher := signal.NewCipher(bobStore, aliceAddr)
	_, err = bobCipher.Decrypt(initMsg)
	require.NoError(t, err)

	manager := signal.NewSesameManager(aliceStore, aliceAddr, time.Hour)
	require.NoError(t, manager.MarkDeviceStale(bobAddr, time.Now()))

	devices, err := manager.NonStaleDevices("bob")
	require.NoError(t, err)
	require.Len(t, devices, 0)

	ct, err := bobCipher.Encrypt([]byte("ping"))
	require.NoError(t, err)

	conv := signal.NewSesameConversation(aliceStore, aliceAddr, time.Hour)
	pt, err := conv.Decrypt(bobAddr, ct)
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), pt)

	devices, err = manager.NonStaleDevices("bob")
	require.NoError(t, err)
	require.Equal(t, []signal.Address{bobAddr}, devices)
}
