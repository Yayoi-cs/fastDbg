package main

import (
	"strings"
)

type NativeSymbolResolver struct {
	dbg *TypeDbg
}

func NewNativeSymbolResolver(dbg *TypeDbg) *NativeSymbolResolver {
	return &NativeSymbolResolver{dbg: dbg}
}

func (r *NativeSymbolResolver) ResolveRegister(name string) (uint64, error) {
	return r.dbg.GetRegs(name)
}

func (r *NativeSymbolResolver) ResolveSymbol(name string) (uint64, error) {
	sym, err := r.dbg.ResolveSymbolToAddr(name)
	if err != nil {
		return 0, err
	}

	actualAddr := sym.Addr
	if sym.LibIndex < len(libRoots) {
		actualAddr += libRoots[sym.LibIndex].base
	}

	return actualAddr, nil
}

func (dbger *TypeDbg) resolveSymbolsNew(cmd string) (string, error) {
	if !strings.Contains(cmd, "$") {
		return cmd, nil
	}

	resolver := NewNativeSymbolResolver(dbger)
	return ResolveSymbolsInCommand(cmd, resolver)
}
