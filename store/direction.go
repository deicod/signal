package store

// Direction indicates message direction for identity trust decisions.
type Direction int

const (
	// DirectionSending indicates evaluating trust when sending to the remote party.
	DirectionSending Direction = iota
	// DirectionReceiving indicates evaluating trust on receipt from the remote party.
	DirectionReceiving
)
