package sealedsender_test

import (
	"testing"

	"github.com/deicod/signal/sealedsender"
	"github.com/stretchr/testify/require"
)

func TestUnidentifiedSenderMessageContentRoundTrip(t *testing.T) {
	fx := buildCertFixture(t)

	content := []byte("ciphertext")
	groupID := []byte("group-1")

	usmc, err := sealedsender.NewUnidentifiedSenderMessageContent(
		sealedsender.MessageTypeSignal,
		fx.senderCert,
		content,
		sealedsender.ContentHintResendable,
		groupID,
	)
	require.NoError(t, err)

	parsed, err := sealedsender.ParseUnidentifiedSenderMessageContent(usmc.Serialize())
	require.NoError(t, err)
	require.Equal(t, sealedsender.MessageTypeSignal, parsed.MessageType())
	require.Equal(t, content, parsed.Content())
	require.Equal(t, sealedsender.ContentHintResendable, parsed.ContentHint())
	require.Equal(t, fx.senderCert.SenderUUID(), parsed.Sender().SenderUUID())
	gid, ok := parsed.GroupID()
	require.True(t, ok)
	require.Equal(t, groupID, gid)
}
