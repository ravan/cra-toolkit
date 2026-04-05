// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package treesitter

// Graph represents a directed call graph of symbols in a project.
type Graph struct {
	symbols map[SymbolID]*Symbol
	forward map[SymbolID][]Edge
	reverse map[SymbolID][]Edge
}

func NewGraph() *Graph {
	return &Graph{
		symbols: make(map[SymbolID]*Symbol),
		forward: make(map[SymbolID][]Edge),
		reverse: make(map[SymbolID][]Edge),
	}
}

func (g *Graph) AddSymbol(sym *Symbol) {
	g.symbols[sym.ID] = sym
}

func (g *Graph) GetSymbol(id SymbolID) *Symbol {
	return g.symbols[id]
}

func (g *Graph) AddEdge(e Edge) {
	g.forward[e.From] = append(g.forward[e.From], e)
	g.reverse[e.To] = append(g.reverse[e.To], e)
}

func (g *Graph) ForwardEdges(id SymbolID) []Edge {
	return g.forward[id]
}

func (g *Graph) ReverseEdges(id SymbolID) []Edge {
	return g.reverse[id]
}

func (g *Graph) EntryPoints() []SymbolID {
	var eps []SymbolID
	for id, sym := range g.symbols {
		if sym.IsEntryPoint {
			eps = append(eps, id)
		}
	}
	return eps
}

func (g *Graph) SymbolCount() int {
	return len(g.symbols)
}

func (g *Graph) AllSymbols() []*Symbol {
	syms := make([]*Symbol, 0, len(g.symbols))
	for _, sym := range g.symbols {
		syms = append(syms, sym)
	}
	return syms
}
