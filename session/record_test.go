package session

import (
	"testing"

	"github.com/deicod/signal/ratchet"
	"github.com/stretchr/testify/require"
)

func TestRecordPromoteAndLimit(t *testing.T) {
	state, localID, remoteID := buildRatchetState(t)
	sess, err := NewSession(state, localID, remoteID, []byte("ad"))
	require.NoError(t, err)

	rec, err := NewRecord(sess, 2)
	require.NoError(t, err)
	require.NotNil(t, rec.Current())
	require.Empty(t, rec.Previous())

	// Promote twice and ensure archive limit
	next := sess.clone()
	next.ratchetState = &ratchet.State{}
	require.NoError(t, rec.Promote(next))
	require.Len(t, rec.Previous(), 1)

	third := next.clone()
	third.ratchetState = &ratchet.State{Ns: 5}
	require.NoError(t, rec.Promote(third))
	require.Len(t, rec.Previous(), 2)

	fourth := third.clone()
	fourth.ratchetState = &ratchet.State{Ns: 9}
	require.NoError(t, rec.Promote(fourth))
	require.Len(t, rec.Previous(), 2) // capped
}

func TestRecordSerializeRoundTrip(t *testing.T) {
	state, localID, remoteID := buildRatchetState(t)
	sess, err := NewSession(state, localID, remoteID, []byte("ad"))
	require.NoError(t, err)

	rec, err := NewRecord(sess, 2)
	require.NoError(t, err)
	wire, err := rec.Serialize()
	require.NoError(t, err)

	decoded, err := DeserializeRecord(wire)
	require.NoError(t, err)
	require.NotNil(t, decoded.Current())
	require.Equal(t, sess.AssociatedData(), decoded.Current().AssociatedData())
	require.Equal(t, sess.version, decoded.Current().version)
}

func TestRecordErrorsOnNil(t *testing.T) {
	_, err := NewRecord(nil, 0)
	require.Error(t, err)

	rec := &Record{}
	_, err = rec.Serialize()
	require.Error(t, err)
}

// buildRatchetState is shared with session tests but kept private here for clarity.
