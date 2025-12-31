package spqr

import (
	"encoding/binary"
	"sort"

	signalcrypto "github.com/deicod/signal/crypto"
)

const (
	chainDefaultMaxJump     uint32 = 25000
	chainDefaultMaxOOO      uint32 = 2000
	epochsToKeepPriorToSend        = 1
)

// ChainParams controls SPQR chain key retention.
type ChainParams struct {
	MaxJump uint32
	MaxOOO  uint32
}

func (p ChainParams) maxJump() uint32 {
	if p.MaxJump == 0 {
		return chainDefaultMaxJump
	}
	return p.MaxJump
}

func (p ChainParams) maxOOO() uint32 {
	if p.MaxOOO == 0 {
		return chainDefaultMaxOOO
	}
	return p.MaxOOO
}

type keyHistory struct {
	keys map[uint32][32]byte
}

func (h *keyHistory) add(idx uint32, key [32]byte) {
	if h.keys == nil {
		h.keys = make(map[uint32][32]byte)
	}
	h.keys[idx] = key
}

func (h *keyHistory) clear() {
	if h.keys == nil {
		return
	}
	for k := range h.keys {
		delete(h.keys, k)
	}
}

func (h *keyHistory) gc(current uint32, maxOOO uint32) {
	if h.keys == nil {
		return
	}
	for idx := range h.keys {
		if idx+maxOOO < current {
			delete(h.keys, idx)
		}
	}
}

func (h *keyHistory) get(idx uint32, current uint32, maxOOO uint32) ([32]byte, error) {
	var out [32]byte
	if idx+maxOOO < current {
		return out, ErrKeyTrimmed
	}
	if h.keys == nil {
		return out, ErrKeyAlreadyRequested
	}
	key, ok := h.keys[idx]
	if !ok {
		return out, ErrKeyAlreadyRequested
	}
	delete(h.keys, idx)
	return key, nil
}

type chainEpochDirection struct {
	ctr  uint32
	next []byte
	prev keyHistory
}

func newChainEpochDirection(seed []byte) chainEpochDirection {
	return chainEpochDirection{
		ctr:  0,
		next: append([]byte(nil), seed...),
		prev: keyHistory{},
	}
}

func (d *chainEpochDirection) nextKey() (uint32, [32]byte, error) {
	if len(d.next) == 0 {
		return 0, [32]byte{}, ErrKeyAlreadyRequested
	}
	d.ctr++
	info := make([]byte, 0, 4+len(chainInfoNext))
	var ctrBytes [4]byte
	binary.BigEndian.PutUint32(ctrBytes[:], d.ctr)
	info = append(info, ctrBytes[:]...)
	info = append(info, chainInfoNext...)

	okm, err := hkdfTo(d.next, nil, info, 64)
	if err != nil {
		return 0, [32]byte{}, err
	}
	var key [32]byte
	copy(d.next, okm[:32])
	copy(key[:], okm[32:])
	return d.ctr, key, nil
}

func (d *chainEpochDirection) key(at uint32, params ChainParams) ([32]byte, error) {
	var zero [32]byte
	maxJump := params.maxJump()
	maxOOO := params.maxOOO()

	switch {
	case at < d.ctr:
		return d.prev.get(at, d.ctr, maxOOO)
	case at == d.ctr:
		return zero, ErrKeyAlreadyRequested
	default:
		if at-d.ctr > maxJump {
			return zero, ErrKeyJump
		}
		if at > d.ctr+maxOOO {
			d.prev.clear()
		}
		for d.ctr+1 < at {
			idx, key, err := d.nextKey()
			if err != nil {
				return zero, err
			}
			if idx+maxOOO >= at {
				d.prev.add(idx, key)
			}
		}
		d.prev.gc(d.ctr, maxOOO)
		_, key, err := d.nextKey()
		if err != nil {
			return zero, err
		}
		return key, nil
	}
}

type chainEpoch struct {
	send chainEpochDirection
	recv chainEpochDirection
}

// Chain tracks SPQR message keys across epochs.
type Chain struct {
	dir          Direction
	currentEpoch uint64
	sendEpoch    uint64
	links        []chainEpoch
	nextRoot     [32]byte
	params       ChainParams
}

var (
	chainInfoStart    = []byte("Signal PQ Ratchet V1 Chain  Start")
	chainInfoAddEpoch = []byte("Signal PQ Ratchet V1 Chain Add Epoch")
	chainInfoNext     = []byte("Signal PQ Ratchet V1 Chain Next")
)

// NewChain creates a new chain with the given auth key.
func NewChain(authKey []byte, dir Direction, params ChainParams) (*Chain, error) {
	okm, err := hkdfTo(authKey, nil, chainInfoStart, 96)
	if err != nil {
		return nil, err
	}
	var root [32]byte
	copy(root[:], okm[:32])
	sendSeed, recvSeed := chainSeedsForDirection(okm, dir)
	return &Chain{
		dir:          dir,
		currentEpoch: 0,
		sendEpoch:    0,
		nextRoot:     root,
		params:       params,
		links: []chainEpoch{{
			send: newChainEpochDirection(sendSeed),
			recv: newChainEpochDirection(recvSeed),
		}},
	}, nil
}

// AddEpoch advances the chain with a new epoch secret.
func (c *Chain) AddEpoch(epoch uint64, secret []byte) error {
	if c == nil {
		return ErrChainNotAvailable
	}
	if epoch != c.currentEpoch+1 {
		return ErrEpochOutOfRange
	}
	okm, err := hkdfTo(secret, c.nextRoot[:], chainInfoAddEpoch, 96)
	if err != nil {
		return err
	}
	copy(c.nextRoot[:], okm[:32])
	sendSeed, recvSeed := chainSeedsForDirection(okm, c.dir)
	c.currentEpoch = epoch
	c.links = append(c.links, chainEpoch{
		send: newChainEpochDirection(sendSeed),
		recv: newChainEpochDirection(recvSeed),
	})
	return nil
}

// SendKey returns the next message key for the given epoch.
func (c *Chain) SendKey(epoch uint64) (uint32, []byte, error) {
	if c == nil {
		return 0, nil, ErrChainNotAvailable
	}
	if epoch < c.sendEpoch {
		return 0, nil, ErrSendKeyEpochDecreased
	}
	idx, err := c.epochIndex(epoch)
	if err != nil {
		return 0, nil, err
	}
	if epoch != c.sendEpoch {
		c.sendEpoch = epoch
		for idx > epochsToKeepPriorToSend {
			c.links = c.links[1:]
			idx--
		}
		for i := 0; i < idx; i++ {
			c.links[i].send.next = nil
		}
	}
	msgIdx, key, err := c.links[idx].send.nextKey()
	if err != nil {
		return 0, nil, err
	}
	return msgIdx, append([]byte(nil), key[:]...), nil
}

// RecvKey returns the message key for the given epoch/index.
func (c *Chain) RecvKey(epoch uint64, index uint32) ([]byte, error) {
	if c == nil {
		return nil, ErrChainNotAvailable
	}
	idx, err := c.epochIndex(epoch)
	if err != nil {
		return nil, err
	}
	key, err := c.links[idx].recv.key(index, c.params)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), key[:]...), nil
}

func (c *Chain) epochIndex(epoch uint64) (int, error) {
	if epoch > c.currentEpoch {
		return 0, ErrEpochOutOfRange
	}
	back := int(c.currentEpoch - epoch)
	if back >= len(c.links) {
		return 0, ErrEpochOutOfRange
	}
	return len(c.links) - 1 - back, nil
}

func chainSeedsForDirection(okm []byte, dir Direction) ([]byte, []byte) {
	switch dir {
	case DirectionA2B:
		return append([]byte(nil), okm[32:64]...), append([]byte(nil), okm[64:96]...)
	case DirectionB2A:
		return append([]byte(nil), okm[64:96]...), append([]byte(nil), okm[32:64]...)
	default:
		return append([]byte(nil), okm[32:64]...), append([]byte(nil), okm[64:96]...)
	}
}

func hkdfTo(ikm []byte, salt []byte, info []byte, length int) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
	}
	return signalcrypto.HKDF(ikm, salt, info, length)
}

// serializeChain encodes the chain state for persistence.
func serializeChain(c *Chain) ([]byte, error) {
	if c == nil {
		return nil, nil
	}
	out := make([]byte, 0, 128)
	out = append(out, byte(1)) // version
	out = append(out, byte(c.dir))
	out = binary.BigEndian.AppendUint64(out, c.currentEpoch)
	out = binary.BigEndian.AppendUint64(out, c.sendEpoch)
	out = append(out, c.nextRoot[:]...)
	out = binary.BigEndian.AppendUint32(out, c.params.MaxJump)
	out = binary.BigEndian.AppendUint32(out, c.params.MaxOOO)
	out = binary.BigEndian.AppendUint32(out, uint32(len(c.links)))
	for _, link := range c.links {
		out = appendChainDir(out, &link.send)
		out = appendChainDir(out, &link.recv)
	}
	return out, nil
}

func appendChainDir(out []byte, dir *chainEpochDirection) []byte {
	out = binary.BigEndian.AppendUint32(out, dir.ctr)
	out = binary.BigEndian.AppendUint32(out, uint32(len(dir.next)))
	out = append(out, dir.next...)
	keys := make([]uint32, 0, len(dir.prev.keys))
	for idx := range dir.prev.keys {
		keys = append(keys, idx)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out = binary.BigEndian.AppendUint32(out, uint32(len(keys)))
	for _, idx := range keys {
		key := dir.prev.keys[idx]
		out = binary.BigEndian.AppendUint32(out, idx)
		out = append(out, key[:]...)
	}
	return out
}

func deserializeChain(data []byte) (*Chain, error) {
	if len(data) == 0 {
		return nil, nil
	}
	pos := 0
	if len(data) < 1 {
		return nil, ErrInvalidMessage
	}
	version := data[pos]
	pos++
	if version != 1 {
		return nil, ErrInvalidMessage
	}
	if pos >= len(data) {
		return nil, ErrInvalidMessage
	}
	dir := Direction(data[pos])
	pos++
	if pos+8+8+32+4+4+4 > len(data) {
		return nil, ErrInvalidMessage
	}
	currentEpoch := binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8
	sendEpoch := binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8
	var nextRoot [32]byte
	copy(nextRoot[:], data[pos:pos+32])
	pos += 32
	params := ChainParams{
		MaxJump: binary.BigEndian.Uint32(data[pos : pos+4]),
		MaxOOO:  binary.BigEndian.Uint32(data[pos+4 : pos+8]),
	}
	pos += 8
	linkCount := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if linkCount < 0 {
		return nil, ErrInvalidMessage
	}
	links := make([]chainEpoch, 0, linkCount)
	for i := 0; i < linkCount; i++ {
		send, npos, err := consumeChainDir(data, pos)
		if err != nil {
			return nil, err
		}
		pos = npos
		recv, npos, err := consumeChainDir(data, pos)
		if err != nil {
			return nil, err
		}
		pos = npos
		links = append(links, chainEpoch{send: send, recv: recv})
	}
	if pos != len(data) {
		return nil, ErrInvalidMessage
	}
	return &Chain{
		dir:          dir,
		currentEpoch: currentEpoch,
		sendEpoch:    sendEpoch,
		nextRoot:     nextRoot,
		params:       params,
		links:        links,
	}, nil
}

func consumeChainDir(data []byte, pos int) (chainEpochDirection, int, error) {
	if pos+4+4 > len(data) {
		return chainEpochDirection{}, pos, ErrInvalidMessage
	}
	ctr := binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	nextLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if nextLen < 0 || pos+nextLen > len(data) {
		return chainEpochDirection{}, pos, ErrInvalidMessage
	}
	next := append([]byte(nil), data[pos:pos+nextLen]...)
	pos += nextLen
	if pos+4 > len(data) {
		return chainEpochDirection{}, pos, ErrInvalidMessage
	}
	keyCount := int(binary.BigEndian.Uint32(data[pos : pos+4]))
	pos += 4
	if keyCount < 0 {
		return chainEpochDirection{}, pos, ErrInvalidMessage
	}
	history := keyHistory{keys: make(map[uint32][32]byte, keyCount)}
	for i := 0; i < keyCount; i++ {
		if pos+4+32 > len(data) {
			return chainEpochDirection{}, pos, ErrInvalidMessage
		}
		idx := binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
		var key [32]byte
		copy(key[:], data[pos:pos+32])
		pos += 32
		history.keys[idx] = key
	}
	return chainEpochDirection{ctr: ctr, next: next, prev: history}, pos, nil
}
