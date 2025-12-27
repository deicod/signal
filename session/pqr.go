package session

import (
	"github.com/deicod/signal/spqr"
	"github.com/deicod/signal/x3dh"
)

func initSessionPQR(session *Session, result *x3dh.Result, isInitiator bool) error {
	if session == nil || result == nil || result.PQRKey == nil {
		return nil
	}
	dir := spqr.DirectionA2B
	if !isInitiator {
		dir = spqr.DirectionB2A
	}
	state, err := spqr.NewState(result.PQRKey[:], dir, spqr.ChainParams{})
	if err != nil {
		return err
	}
	session.pqrState = state
	return nil
}
