package config

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Config(t *testing.T) {
	require.NotEqual(t, reflect.ValueOf(Default).Kind(), reflect.Pointer)

	var cfg = Default

	WalkNotPtr(t, cfg)
}

func WalkNotPtr(t require.TestingT, p any) {
	v := reflect.ValueOf(p)
	walkNotPtr(t, v)
}

func walkNotPtr(t require.TestingT, v reflect.Value) {
	switch v.Kind() {
	case reflect.Bool:
	case reflect.Int:
	case reflect.Int8:
	case reflect.Int16:
	case reflect.Int32:
	case reflect.Int64:
	case reflect.Uint:
	case reflect.Uint8:
	case reflect.Uint16:
	case reflect.Uint32:
	case reflect.Uint64:
	case reflect.Uintptr:
	case reflect.Float32:
	case reflect.Float64:
	case reflect.Complex64:
	case reflect.Complex128:
	case reflect.Array:
		walkNotPtr(t, v.Elem())
	case reflect.Chan:
		t.FailNow()
	case reflect.Func:
		t.FailNow()
	case reflect.Interface:
		t.FailNow()
	case reflect.Map:
		t.FailNow()
	case reflect.Pointer:
		t.FailNow()
	case reflect.Slice:
		t.FailNow()
	case reflect.String:
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			walkNotPtr(t, v.Field(i))
		}
	case reflect.UnsafePointer:
		t.FailNow()
	default:
		panic("")
	}
}
