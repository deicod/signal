package spqr

import (
	"errors"
	"sort"
)

const (
	polyNumPolys                = 16
	polyChunkDataSize           = 32
	maxStoredPolynomialDegreeV1 = 35
)

type chunk struct {
	index uint16
	data  [polyChunkDataSize]byte
}

type polynomialError string

func (e polynomialError) Error() string {
	return string(e)
}

const (
	errPolyMessageLengthEven polynomialError = "spqr: polynomial message length must be even"
	errPolyMessageTooLong    polynomialError = "spqr: polynomial message length too long"
)

type poly struct {
	coeffs []gf16
}

func (p *poly) eval(x gf16) gf16 {
	if len(p.coeffs) == 0 {
		return gf16Zero
	}
	out := p.coeffs[len(p.coeffs)-1]
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		out = out.mul(x).add(p.coeffs[i])
		if i == 0 {
			break
		}
	}
	return out
}

func polyAdd(a, b []gf16) []gf16 {
	if len(a) < len(b) {
		a, b = b, a
	}
	out := make([]gf16, len(a))
	copy(out, a)
	for i := range b {
		out[i] = out[i].add(b[i])
	}
	return out
}

func polyMul(a, b []gf16) []gf16 {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	out := make([]gf16, len(a)+len(b)-1)
	for i := range a {
		for j := range b {
			out[i+j] = out[i+j].add(a[i].mul(b[j]))
		}
	}
	return out
}

func polyScale(a []gf16, s gf16) []gf16 {
	if len(a) == 0 {
		return nil
	}
	out := make([]gf16, len(a))
	for i := range a {
		out[i] = a[i].mul(s)
	}
	return out
}

func lagrangeInterpolate(points []point) *poly {
	if len(points) == 0 {
		return &poly{coeffs: nil}
	}
	coeffs := make([]gf16, len(points))
	for i, pi := range points {
		basis := []gf16{gf16One}
		denom := gf16One
		for j, pj := range points {
			if i == j {
				continue
			}
			// (x - xj) == (x + xj) in GF(2^m)
			basis = polyMul(basis, []gf16{pj.x, gf16One})
			denom = denom.mul(pi.x.add(pj.x))
		}
		if denom == 0 {
			continue
		}
		scale := pi.y.div(denom)
		basis = polyScale(basis, scale)
		coeffs = polyAdd(coeffs, basis)
	}
	return &poly{coeffs: coeffs}
}

type point struct {
	x gf16
	y gf16
}

type polyEncoder struct {
	idx    uint32
	msg    []byte
	points [polyNumPolys][]gf16
	polys  [polyNumPolys]*poly
}

func newPolyEncoder(msg []byte) (*polyEncoder, error) {
	if len(msg)%2 != 0 {
		return nil, errPolyMessageLengthEven
	}
	if len(msg) > (1<<16)*polyNumPolys {
		return nil, errPolyMessageTooLong
	}
	enc := &polyEncoder{msg: append([]byte(nil), msg...)}
	for i := 0; i < polyNumPolys; i++ {
		enc.points[i] = make([]gf16, 0, len(msg)/2)
	}
	for i := 0; i < len(msg); i += 2 {
		idx := (i / 2) % polyNumPolys
		value := uint16(msg[i])<<8 | uint16(msg[i+1])
		enc.points[idx] = append(enc.points[idx], newGF16(value))
	}
	return enc, nil
}

func (e *polyEncoder) pointAt(polyIdx int, idx int) gf16 {
	if idx < len(e.points[polyIdx]) {
		return e.points[polyIdx][idx]
	}
	if e.polys[0] == nil {
		for i := 0; i < polyNumPolys; i++ {
			pts := make([]point, len(e.points[i]))
			for j, y := range e.points[i] {
				pts[j] = point{x: newGF16(uint16(j)), y: y}
			}
			e.polys[i] = lagrangeInterpolate(pts)
		}
	}
	return e.polys[polyIdx].eval(newGF16(uint16(idx)))
}

func (e *polyEncoder) chunkAt(idx uint16) chunk {
	var out chunk
	out.index = idx
	for i := 0; i < polyNumPolys; i++ {
		totalIdx := int(idx)*polyNumPolys + i
		poly := totalIdx % polyNumPolys
		polyIdx := totalIdx / polyNumPolys
		value := e.pointAt(poly, polyIdx)
		out.data[i*2] = byte(uint16(value) >> 8)
		out.data[i*2+1] = byte(value)
	}
	return out
}

func (e *polyEncoder) nextChunk() chunk {
	out := e.chunkAt(uint16(e.idx))
	e.idx++
	return out
}

func (e *polyEncoder) serialize() []byte {
	if e == nil {
		return nil
	}
	out := make([]byte, 0, 8+len(e.msg))
	out = appendUint32(out, e.idx)
	out = appendUint32(out, uint32(len(e.msg)))
	out = append(out, e.msg...)
	return out
}

func decodePolyEncoder(data []byte) (*polyEncoder, error) {
	if len(data) < 8 {
		return nil, ErrStateDecode
	}
	idx := readUint32(data[:4])
	msgLen := int(readUint32(data[4:8]))
	if msgLen < 0 || 8+msgLen > len(data) {
		return nil, ErrStateDecode
	}
	msg := data[8 : 8+msgLen]
	enc, err := newPolyEncoder(msg)
	if err != nil {
		return nil, err
	}
	enc.idx = idx
	return enc, nil
}

type polyDecoder struct {
	ptsNeeded  int
	points     [polyNumPolys]map[uint16]gf16
	isComplete bool
}

func newPolyDecoder(lenBytes int) (*polyDecoder, error) {
	if lenBytes%2 != 0 {
		return nil, errPolyMessageLengthEven
	}
	dec := &polyDecoder{
		ptsNeeded: lenBytes / 2,
	}
	for i := 0; i < polyNumPolys; i++ {
		dec.points[i] = make(map[uint16]gf16)
	}
	return dec, nil
}

func (d *polyDecoder) necessaryPoints(poly int) int {
	pointsPerPoly := d.ptsNeeded / polyNumPolys
	pointsRemaining := d.ptsNeeded % polyNumPolys
	if poly < pointsRemaining {
		return pointsPerPoly + 1
	}
	return pointsPerPoly
}

func (d *polyDecoder) addChunk(c *chunk) {
	for i := 0; i < polyNumPolys; i++ {
		totalIdx := int(c.index)*polyNumPolys + i
		poly := totalIdx % polyNumPolys
		polyIdx := totalIdx / polyNumPolys
		x := uint16(polyIdx)
		value := uint16(c.data[i*2])<<8 | uint16(c.data[i*2+1])
		needed := d.necessaryPoints(i)
		if polyIdx < needed || len(d.points[poly]) < needed {
			if _, ok := d.points[poly][x]; !ok {
				d.points[poly][x] = newGF16(value)
			}
		}
	}
}

func (d *polyDecoder) sortedPoints(polyIdx int, needed int) []point {
	pts := d.points[polyIdx]
	keys := make([]int, 0, len(pts))
	for k := range pts {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	if needed > len(keys) {
		needed = len(keys)
	}
	out := make([]point, 0, needed)
	for i := 0; i < needed; i++ {
		x := uint16(keys[i])
		out = append(out, point{x: newGF16(x), y: pts[x]})
	}
	return out
}

func (d *polyDecoder) decodedMessage() ([]byte, error) {
	if d.isComplete {
		return nil, nil
	}
	pointsVecs := make([][]point, polyNumPolys)
	for i := 0; i < polyNumPolys; i++ {
		needed := d.necessaryPoints(i)
		if len(d.points[i]) < needed {
			return nil, nil
		}
		pointsVecs[i] = d.sortedPoints(i, needed)
		if len(pointsVecs[i]) == 0 {
			return nil, errors.New("spqr: polynomial decode missing points")
		}
	}
	polys := make([]*poly, polyNumPolys)
	out := make([]byte, 0, d.ptsNeeded*2)
	for i := 0; i < d.ptsNeeded; i++ {
		poly := i % polyNumPolys
		polyIdx := i / polyNumPolys
		x := uint16(polyIdx)
		value, ok := d.points[poly][x]
		if !ok {
			if polys[poly] == nil {
				polys[poly] = lagrangeInterpolate(pointsVecs[poly])
			}
			value = polys[poly].eval(newGF16(x))
		}
		out = append(out, byte(uint16(value)>>8), byte(value))
	}
	return out, nil
}

func (d *polyDecoder) serialize() []byte {
	if d == nil {
		return nil
	}
	out := make([]byte, 0, 8+polyNumPolys*4)
	out = appendUint32(out, uint32(d.ptsNeeded))
	if d.isComplete {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	for i := 0; i < polyNumPolys; i++ {
		keys := make([]int, 0, len(d.points[i]))
		for k := range d.points[i] {
			keys = append(keys, int(k))
		}
		sort.Ints(keys)
		out = appendUint32(out, uint32(len(keys)))
		for _, k := range keys {
			out = appendUint16(out, uint16(k))
			out = appendUint16(out, uint16(d.points[i][uint16(k)]))
		}
	}
	return out
}

func decodePolyDecoder(data []byte) (*polyDecoder, error) {
	if len(data) < 5 {
		return nil, ErrStateDecode
	}
	pos := 0
	ptsNeeded := int(readUint32(data[pos : pos+4]))
	pos += 4
	isComplete := data[pos] == 1
	pos++
	dec := &polyDecoder{
		ptsNeeded:  ptsNeeded,
		isComplete: isComplete,
	}
	for i := 0; i < polyNumPolys; i++ {
		dec.points[i] = make(map[uint16]gf16)
		if pos+4 > len(data) {
			return nil, ErrStateDecode
		}
		count := int(readUint32(data[pos : pos+4]))
		pos += 4
		if count < 0 {
			return nil, ErrStateDecode
		}
		for j := 0; j < count; j++ {
			if pos+4 > len(data) {
				return nil, ErrStateDecode
			}
			x := readUint16(data[pos : pos+2])
			y := readUint16(data[pos+2 : pos+4])
			pos += 4
			dec.points[i][x] = newGF16(y)
		}
	}
	if pos != len(data) {
		return nil, ErrStateDecode
	}
	return dec, nil
}
