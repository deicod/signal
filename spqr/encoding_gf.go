package spqr

const gf16Poly uint32 = 0x1100b

type gf16 uint16

const (
	gf16Zero gf16 = 0
	gf16One  gf16 = 1
)

func newGF16(v uint16) gf16 {
	return gf16(v)
}

func (a gf16) add(b gf16) gf16 {
	return a ^ b
}

func (a gf16) sub(b gf16) gf16 {
	return a ^ b
}

func (a gf16) mul(b gf16) gf16 {
	return gf16(gf16Reduce(gf16Mul(uint16(a), uint16(b))))
}

func (a gf16) div(b gf16) gf16 {
	if b == 0 {
		return 0
	}
	return a.mul(gf16Pow(b, 65534))
}

func gf16Pow(a gf16, exp uint32) gf16 {
	result := gf16One
	base := a
	for exp > 0 {
		if exp&1 == 1 {
			result = result.mul(base)
		}
		base = base.mul(base)
		exp >>= 1
	}
	return result
}

func gf16Mul(a, b uint16) uint32 {
	var acc uint32
	aa := uint32(a)
	bb := uint32(b)
	for i := 0; i < 16; i++ {
		if (bb>>uint(i))&1 == 1 {
			acc ^= aa << uint(i)
		}
	}
	return acc
}

func gf16Reduce(v uint32) uint16 {
	for i := 31; i >= 16; i-- {
		if (v>>uint(i))&1 == 1 {
			v ^= gf16Poly << uint(i-16)
		}
	}
	return uint16(v)
}
