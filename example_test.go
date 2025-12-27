package signal_test

import (
	"context"
	"fmt"
	"time"

	"github.com/deicod/signal"
	"github.com/deicod/signal/store/memory"
)

type exampleRosterProvider struct {
	devices []signal.SesameDevice
	bundles map[signal.Address]*signal.PreKeyBundle
}

func (p *exampleRosterProvider) DeviceList(_ context.Context, _ string) ([]signal.SesameDevice, error) {
	return p.devices, nil
}

func (p *exampleRosterProvider) PreKeyBundle(_ context.Context, addr signal.Address) (*signal.PreKeyBundle, error) {
	return p.bundles[addr], nil
}

func ExampleCipher() {
	aliceID, _ := signal.GenerateIdentityKeyPair()
	bobID, _ := signal.GenerateIdentityKeyPair()

	// Each side has its own ProtocolStore (memory store used here for brevity).
	aliceStore := memory.NewStore(aliceID, 1)
	bobStore := memory.NewStore(bobID, 2)

	// Bob publishes a pre-key bundle (signed pre-key + identity).
	signed, _ := signal.GenerateAndStoreSignedPreKey(bobStore, 1)
	kyber, _ := signal.GenerateAndStoreKyberPreKey(bobStore, 2)
	bundle, _ := signal.BuildPreKeyBundle(bobStore, 1, nil, signed.ID, &kyber.ID)

	aliceToBob := signal.NewCipher(aliceStore, signal.Address{Name: "bob", Device: 1})
	bobToAlice := signal.NewCipher(bobStore, signal.Address{Name: "alice", Device: 1})

	// First message bootstraps a session (X3DH + first Double Ratchet ciphertext).
	first, _ := aliceToBob.EncryptWithPreKeyBundle(bundle, []byte("hello"))
	plain, _ := bobToAlice.Decrypt(first)
	fmt.Println(string(plain))

	// Subsequent messages use the established session.
	next, _ := bobToAlice.Encrypt([]byte("pong"))
	plain, _ = aliceToBob.Decrypt(next)
	fmt.Println(string(plain))

	// Output:
	// hello
	// pong
}

func ExampleGroupCipher() {
	aliceID, _ := signal.GenerateIdentityKeyPair()
	bobID, _ := signal.GenerateIdentityKeyPair()

	aliceStore := memory.NewStore(aliceID, 1)
	bobStore := memory.NewStore(bobID, 2)

	groupID := "group-1"
	aliceAddr := signal.Address{Name: "alice", Device: 1}

	// Alice creates a sender key state and distributes it to Bob (usually via a 1:1 session).
	name := signal.SenderKeyName{Group: groupID, Sender: aliceAddr}
	dist, _ := signal.NewGroupSessionBuilder(aliceStore, name).Create()
	_ = signal.NewGroupSessionBuilder(bobStore, name).Process(dist)

	aliceGroup := signal.NewGroupCipher(aliceStore, name)
	bobFromAlice := signal.NewGroupCipher(bobStore, name)

	ct, _ := aliceGroup.Encrypt([]byte("hello group"))
	pt, _ := bobFromAlice.Decrypt(ct)
	fmt.Println(string(pt))

	// Output:
	// hello group
}

func ExampleSesameConversation() {
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

	provider := &exampleRosterProvider{
		devices: []signal.SesameDevice{
			{DeviceID: 1, IdentityKey: &bundle1.IdentityKey},
			{DeviceID: 2, IdentityKey: &bundle2.IdentityKey},
		},
		bundles: map[signal.Address]*signal.PreKeyBundle{
			bob1Addr: bundle1,
			bob2Addr: bundle2,
		},
	}

	conv := signal.NewSesameConversation(aliceStore, aliceAddr, time.Hour)
	out, _ := conv.EncryptWithRoster(context.Background(), "bob", []byte("hello"), provider, time.Unix(0, 0))

	bob1Cipher := signal.NewCipher(bob1Store, aliceAddr)
	pt, _ := bob1Cipher.Decrypt(out[bob1Addr])
	fmt.Println(string(pt))

	bob2Cipher := signal.NewCipher(bob2Store, aliceAddr)
	pt, _ = bob2Cipher.Decrypt(out[bob2Addr])
	fmt.Println(string(pt))

	// Output:
	// hello
	// hello
}
