package treesitter

import (
	"github.com/ravan/suse-cra-toolkit/pkg/formats"
	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability"
)

// ReachabilityConfig controls the BFS pathfinding behavior.
type ReachabilityConfig struct {
	MaxDepth int
	MaxPaths int
}

type bfsNode struct {
	id   SymbolID
	path []SymbolID
}

// FindReachablePaths performs BFS from each entry point to the target symbol.
func FindReachablePaths(g *Graph, entryPoints []SymbolID, target SymbolID, cfg ReachabilityConfig) []reachability.CallPath {
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 50
	}
	if cfg.MaxPaths == 0 {
		cfg.MaxPaths = 5
	}

	var allPaths []reachability.CallPath
	for _, ep := range entryPoints {
		if len(allPaths) >= cfg.MaxPaths {
			break
		}
		paths := bfs(g, ep, target, cfg.MaxDepth, cfg.MaxPaths-len(allPaths))
		allPaths = append(allPaths, paths...)
	}
	return allPaths
}

func bfs(g *Graph, start, target SymbolID, maxDepth, maxPaths int) []reachability.CallPath {
	if start == target {
		sym := g.GetSymbol(start)
		node := reachability.CallNode{Symbol: string(start)}
		if sym != nil {
			node.File = sym.File
			node.Line = sym.StartLine
		}
		return []reachability.CallPath{{Nodes: []reachability.CallNode{node}}}
	}

	var results []reachability.CallPath
	visited := make(map[SymbolID]bool)
	queue := []bfsNode{{id: start, path: []SymbolID{start}}}
	visited[start] = true

	for len(queue) > 0 && len(results) < maxPaths {
		current := queue[0]
		queue = queue[1:]

		if len(current.path) > maxDepth {
			continue
		}

		for _, edge := range g.ForwardEdges(current.id) {
			if edge.To == target {
				fullPath := append(current.path, target)
				callPath := symbolsToCallPath(g, fullPath)
				results = append(results, callPath)
				if len(results) >= maxPaths {
					return results
				}
				continue
			}

			if !visited[edge.To] {
				visited[edge.To] = true
				newPath := make([]SymbolID, len(current.path)+1)
				copy(newPath, current.path)
				newPath[len(current.path)] = edge.To
				queue = append(queue, bfsNode{id: edge.To, path: newPath})
			}
		}
	}

	return results
}

func symbolsToCallPath(g *Graph, ids []SymbolID) reachability.CallPath {
	nodes := make([]reachability.CallNode, len(ids))
	for i, id := range ids {
		nodes[i] = reachability.CallNode{Symbol: string(id)}
		if sym := g.GetSymbol(id); sym != nil {
			nodes[i].File = sym.File
			nodes[i].Line = sym.StartLine
		}
	}
	return reachability.CallPath{Nodes: nodes}
}

// PathConfidence computes the confidence of a call path as product of edge confidences.
func PathConfidence(g *Graph, path reachability.CallPath) float64 {
	if len(path.Nodes) < 2 {
		return 1.0
	}
	conf := 1.0
	for i := 0; i < len(path.Nodes)-1; i++ {
		from := SymbolID(path.Nodes[i].Symbol)
		to := SymbolID(path.Nodes[i+1].Symbol)
		edgeConf := 0.0
		for _, edge := range g.ForwardEdges(from) {
			if edge.To == to {
				edgeConf = edge.Confidence
				break
			}
		}
		if edgeConf == 0 {
			edgeConf = 1.0
		}
		conf *= edgeConf
	}
	return conf
}

// MapConfidence maps a numeric path confidence to a formats.Confidence level.
func MapConfidence(pathConf float64) formats.Confidence {
	switch {
	case pathConf >= 0.8:
		return formats.ConfidenceHigh
	case pathConf >= 0.4:
		return formats.ConfidenceMedium
	default:
		return formats.ConfidenceLow
	}
}
