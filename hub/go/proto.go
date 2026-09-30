package main

import (
	"encoding/binary"
	"errors"
)

// A minimal protobuf encoder and decoder for the few auth messages the hub
// sends and reads. Generated code for Teleport's API would be far larger
// than the handful of fields the hub needs. Like proto3, the encoder leaves
// out empty strings and bytes and zero numbers.

// pb builds one message.
type pb []byte

func (m pb) tag(field, wire int) pb { return binary.AppendUvarint(m, uint64(field<<3|wire)) }

func (m pb) str(field int, s string) pb {
	if s == "" {
		return m
	}
	m = m.tag(field, 2)
	m = binary.AppendUvarint(m, uint64(len(s)))
	return append(m, s...)
}

func (m pb) bytes(field int, b []byte) pb {
	if len(b) == 0 {
		return m
	}
	m = m.tag(field, 2)
	m = binary.AppendUvarint(m, uint64(len(b)))
	return append(m, b...)
}

// msg adds a sub-message, even an empty one, as prost does for a set
// optional field.
func (m pb) msg(field int, sub pb) pb {
	m = m.tag(field, 2)
	m = binary.AppendUvarint(m, uint64(len(sub)))
	return append(m, sub...)
}

func (m pb) int(field int, v int64) pb {
	if v == 0 {
		return m
	}
	return binary.AppendUvarint(m.tag(field, 0), uint64(v))
}

// fields is a decoded message: each field number with its values in
// order. A varint value is in num, a length-delimited one in raw.
type fields map[int][]value

type value struct {
	num uint64
	raw []byte
}

var errProto = errors.New("bad protobuf")

func decode(b []byte) (fields, error) {
	f := make(fields)
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errProto
		}
		b = b[n:]
		field, wire := int(key>>3), int(key&7)
		var v value
		switch wire {
		case 0:
			v.num, n = binary.Uvarint(b)
			if n <= 0 {
				return nil, errProto
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errProto
			}
			v.num = binary.LittleEndian.Uint64(b)
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return nil, errProto
			}
			v.raw = b[n : n+int(l)]
			b = b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return nil, errProto
			}
			v.num = uint64(binary.LittleEndian.Uint32(b))
			b = b[4:]
		default:
			return nil, errProto
		}
		f[field] = append(f[field], v)
	}
	return f, nil
}

// last returns the last value of a field, which is what protobuf keeps for
// a field that is not repeated.
func (f fields) last(field int) (value, bool) {
	vs := f[field]
	if len(vs) == 0 {
		return value{}, false
	}
	return vs[len(vs)-1], true
}

func (f fields) str(field int) string {
	v, _ := f.last(field)
	return string(v.raw)
}

func (f fields) bytes(field int) []byte {
	v, _ := f.last(field)
	return v.raw
}

func (f fields) int(field int) int64 {
	v, _ := f.last(field)
	return int64(v.num)
}

// msg returns a sub-message, or nil fields if it is not set or does not
// decode.
func (f fields) msg(field int) fields {
	v, ok := f.last(field)
	if !ok {
		return nil
	}
	m, err := decode(v.raw)
	if err != nil {
		return nil
	}
	return m
}

// msgs returns every value of a repeated sub-message field.
func (f fields) msgs(field int) []fields {
	var out []fields
	for _, v := range f[field] {
		if m, err := decode(v.raw); err == nil {
			out = append(out, m)
		}
	}
	return out
}

func (f fields) has(field int) bool { return len(f[field]) > 0 }
