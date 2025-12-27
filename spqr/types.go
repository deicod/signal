package spqr

// Version represents the SPQR protocol version.
type Version uint8

const (
	// VersionDisabled disables SPQR negotiation and messages.
	VersionDisabled Version = 0
	// VersionV1 enables SPQR v1 messaging.
	VersionV1 Version = 1
)

// Direction indicates the local sender->receiver direction.
type Direction uint8

const (
	// DirectionA2B indicates local A -> remote B direction.
	DirectionA2B Direction = iota
	// DirectionB2A indicates local B -> remote A direction.
	DirectionB2A
)

// Switch returns the opposite direction.
func (d Direction) Switch() Direction {
	if d == DirectionA2B {
		return DirectionB2A
	}
	return DirectionA2B
}
