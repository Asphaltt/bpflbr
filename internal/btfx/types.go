// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package btfx

import (
	"fmt"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/btf"
)

func IsPointer(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	_, ok := t.(*btf.Pointer)
	return ok
}

func IsEnum(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	_, ok := t.(*btf.Enum)
	return ok
}

func IsNumberPointer(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	ptr, ok := t.(*btf.Pointer)
	return ok && (mybtf.IsInt(ptr.Target) || mybtf.IsBool(ptr.Target) || IsEnum(ptr.Target))
}

func IsSigned(t btf.Type) bool {
	t = mybtf.UnderlyingType(t)
	i, ok := t.(*btf.Int)
	return ok && i.Encoding == btf.Signed
}

func IsConst(t btf.Type) bool {
	for {
		switch v := t.(type) {
		case *btf.Typedef:
			t = v.Type
		case *btf.Volatile:
			t = v.Type
		case *btf.Const:
			return true
		case *btf.Restrict:
			t = v.Type
		default:
			return false
		}
	}
}

func IsStr(t btf.Type) bool {
	ptr, ok := t.(*btf.Pointer)
	if !ok {
		return false
	}

	cnst, ok := ptr.Target.(*btf.Const)
	if !ok {
		return false
	}

	i, ok := cnst.Type.(*btf.Int)
	return ok && i.Name == "char"
}

func Repr(t btf.Type) string {
	var sb strings.Builder

loop:
	for {
		switch v := t.(type) {
		case *btf.Typedef:
			t = v.Type
			return v.Name
		case *btf.Volatile:
			t = v.Type
			fmt.Fprint(&sb, "volatile ")
		case *btf.Const:
			t = v.Type
			fmt.Fprint(&sb, "const ")
		case *btf.Restrict:
			t = v.Type
			fmt.Fprint(&sb, "restrict ")
		case *btf.TypeTag:
			t = v.Type
			fmt.Fprint(&sb, v.Value, " ")
		default:
			break loop
		}
	}

	ptr, isPtr := t.(*btf.Pointer)
	if isPtr {
		t = ptr.Target
		r := Repr(t)
		fmt.Fprint(&sb, r)
		if r[len(r)-1] != '*' {
			fmt.Fprint(&sb, " *")
		} else {
			fmt.Fprint(&sb, "*") // pointer to pointer ...
		}
		return sb.String()
	}

	switch v := t.(type) {
	case *btf.Void:
		fmt.Fprint(&sb, "void")

	case *btf.Int:
		switch v.Encoding {
		case btf.Unsigned:
			fmt.Fprint(&sb, "unsigned ", v.Name)
		case btf.Signed:
			fmt.Fprint(&sb, "signed ", v.Name)
		case btf.Char:
			fmt.Fprint(&sb, "char")
		case btf.Bool:
			fmt.Fprint(&sb, "bool")
		default:
			fmt.Fprint(&sb, "int")
		}

	case *btf.Enum:
		fmt.Fprintf(&sb, "enum %s", v.Name)

	case *btf.Struct:
		fmt.Fprintf(&sb, "struct %s", v.Name)

	case *btf.Union:
		fmt.Fprintf(&sb, "union %s", v.Name)

	case *btf.Func:
		fmt.Fprintf(&sb, "func %s", v.Name)

	case *btf.Float:
		fmt.Fprint(&sb, "float")

	case *btf.Array:
		fmt.Fprintf(&sb, "array(%s)[%d]", Repr(v.Type), v.Nelems)

	default:
		fmt.Fprintf(&sb, "%v", t)
	}

	return sb.String()
}

func ReprValue(t btf.Type, val uint64) string {
	t = mybtf.UnderlyingType(t)

	var sb strings.Builder

	size, err := btf.Sizeof(t)
	if err != nil {
		fmt.Fprintf(&sb, "..ERR..")
		return sb.String()
	}

	isPtr := IsPointer(t)
	isSignedInt := IsSigned(t)

	switch size {
	case 8:
		if isPtr {
			fmt.Fprintf(&sb, "%#x", val)
		} else {
			if isSignedInt {
				fmt.Fprintf(&sb, "%d", int64(val))
			} else {
				fmt.Fprintf(&sb, "%#x/%d", val, val)
			}
		}

	case 4:
		if isSignedInt {
			fmt.Fprintf(&sb, "%d", int32(val))
		} else {
			fmt.Fprintf(&sb, "%#x/%d", uint32(val), uint32(val))
		}
	case 2:
		if isSignedInt {
			fmt.Fprintf(&sb, "%d", int16(val))
		} else {
			fmt.Fprintf(&sb, "%#x/%d", uint16(val), uint16(val))
		}
	case 1:
		if isSignedInt {
			fmt.Fprintf(&sb, "%d", int8(val))
		} else {
			fmt.Fprintf(&sb, "%#x/%d", uint8(val), uint8(val))
		}
	default:
		fmt.Fprintf(&sb, "..UNK..")
	}

	return sb.String()
}

func ReprFuncParam(param *btf.FuncParam, i int, isStr, isNumberPtr bool, data, data2 uint64, s string) string {
	var sb strings.Builder

	typ := param.Type
	fmt.Fprintf(&sb, "(%v)", Repr(typ))

	size, err := btf.Sizeof(typ)
	if err != nil {
		fmt.Fprintf(&sb, "arg[%d]=..ERR..", i)
		return sb.String()
	}

	fmt.Fprint(&sb, param.Name, "=")

	if size == 8 && (isStr || isNumberPtr) {
		if isStr {
			fmt.Fprintf(&sb, "\"%s\"", s)
		} else {
			typ = mybtf.UnderlyingType(typ).(*btf.Pointer).Target
			fmt.Fprintf(&sb, "%#x(%s)", data, ReprValue(typ, data2))
		}
	} else {
		fmt.Fprint(&sb, ReprValue(typ, data))
	}

	return sb.String()
}

func ReprFuncReturn(typ btf.Type, val int64) string {
	typ = mybtf.UnderlyingType(typ)
	if _, ok := typ.(*btf.Void); ok {
		return "(void)"
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "(%v)", Repr(typ))
	fmt.Fprint(&sb, ReprValue(typ, uint64(val)))

	return sb.String()
}
