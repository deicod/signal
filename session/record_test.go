package session

import (
	"testing"

	signalerrors "github.com/deicod/signal/errors"
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

func TestRecordSerializeHeader(t *testing.T) {
	state, localID, remoteID := buildRatchetState(t)
	sess, err := NewSession(state, localID, remoteID, nil)
	require.NoError(t, err)

	rec, err := NewRecord(sess, 1)
	require.NoError(t, err)
	wire, err := rec.Serialize()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(wire), 5)
	require.Equal(t, []byte("SIGR"), wire[:4])
	require.Equal(t, byte(1), wire[4])
}

func TestDeserializeRecordRejectsBadData(t *testing.T) {
	_, err := DeserializeRecord(nil)
	require.ErrorIs(t, err, signalerrors.ErrInvalidMessage)

	_, err = DeserializeRecord([]byte("nope"))
	require.ErrorIs(t, err, signalerrors.ErrInvalidMessage)
}

func TestRecordSerializeDeterministic(t *testing.T) {
	state, localID, remoteID := buildRatchetState(t)
	sess, err := NewSession(state, localID, remoteID, []byte("ad"))
	require.NoError(t, err)

	rec, err := NewRecord(sess, 2)
	require.NoError(t, err)

	next := sess.clone()
	next.ratchetState = state.Clone()
	next.ratchetState.Ns++
	require.NoError(t, rec.Promote(next))

	wire1, err := rec.Serialize()
	require.NoError(t, err)
	wire2, err := rec.Serialize()
	require.NoError(t, err)
	require.Equal(t, wire1, wire2)

	decoded, err := DeserializeRecord(wire1)
	require.NoError(t, err)
	wire3, err := decoded.Serialize()
	require.NoError(t, err)
	require.Equal(t, wire1, wire3)
}

// buildRatchetState is shared with session tests but kept private here for clarity.
