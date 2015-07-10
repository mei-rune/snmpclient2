package snmpclient2

import (
	"errors"
	"math"
)

func AsInt(value Variable) (int, error) {
	a, err := AsInt32(value)
	return int(a), err
}

func AsUint(value Variable) (uint, error) {
	a, err := AsUint32(value)
	return uint(a), err
}

// Int type AsSerts to `float64` then converts to `int`
func AsInt64(value Variable) (int64, error) {
	switch value.Syntex() {
	case SYNTAX_INTEGER:
		return value.Int(), nil
	case SYNTAX_GAUGE32, SYNTAX_COUNTER32, SYNTAX_TIMETICKS:
		return value.Int(), nil
	case SYNTAX_COUNTER64:
		if math.MaxInt64 < value.Uint() {
			return 0, errors.New("type Assertion to int64 failed, it is too big.")
		}
		return int64(value.Uint()), nil
	}
	return 0, errors.New("type Assertion to int64 failed")
}

func AsInt32(value Variable) (int32, error) {
	switch value.Syntex() {
	case SYNTAX_INTEGER:
		return int32(value.Int()), nil
	case SYNTAX_GAUGE32, SYNTAX_COUNTER32, SYNTAX_TIMETICKS, SYNTAX_COUNTER64:
		u32 := value.Uint()
		if math.MaxInt32 < u32 {
			return 0, errors.New("type Assertion to int32 failed, it is too big.")
		}
		return int32(u32), nil
	}
	return 0, errors.New("type Assertion to int64 failed")
}

// Uint type AsSerts to `float64` then converts to `int`
func AsUint64(value Variable) (uint64, error) {
	switch value.Syntex() {
	case SYNTAX_INTEGER:
		if 0 <= value.Int() {
			return uint64(value.Int()), nil
		}
	case SYNTAX_GAUGE32, SYNTAX_COUNTER32, SYNTAX_TIMETICKS, SYNTAX_COUNTER64:
		return value.Uint(), nil
	}
	return 0, errors.New("type Assertion to uint64 failed")
}

func AsUint32(value Variable) (uint32, error) {
	switch value.Syntex() {
	case SYNTAX_INTEGER:
		if 0 <= value.Int() {
			return uint32(value.Int()), nil
		}
	case SYNTAX_GAUGE32, SYNTAX_COUNTER32, SYNTAX_TIMETICKS:
		return uint32(value.Uint()), nil
	case SYNTAX_COUNTER64:
		u64 := value.Uint()
		if math.MaxUint32 < u64 {
			return 0, errors.New("type AsUint32 to uint32 failed, it is too big.")
		}
		return uint32(u64), nil
	}
	return 0, errors.New("type Assertion to uint32 failed")
}
