package javascript

import (
	"path/filepath"
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

// httpMethods is an alias for routeRegistrationMethods used for route-handler name heuristics.
// "use" and "route" are excluded from the prefix-match heuristic since they don't produce
// named handlers like getUser or postItem.
var httpMethods = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "head": true, "options": true, "all": true,
}

// svelteKitHTTPExports are the exported function names that SvelteKit treats as route handlers.
var svelteKitHTTPExports = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true, "fallback": true,
}

// remixExports are exported function names that Remix/React Router treats as data loaders/actions.
var remixExports = map[string]bool{
	"loader": true, "action": true, "clientLoader": true, "clientAction": true,
}

// nextjsExports are exported function/const names that Next.js treats as lifecycle hooks.
var nextjsExports = map[string]bool{
	"getServerSideProps": true, "getStaticProps": true,
	"getStaticPaths": true, "middleware": true,
}

// nestjsHTTPDecorators are NestJS method decorator names that mark route handlers.
var nestjsHTTPDecorators = []string{
	"@Get", "@Post", "@Put", "@Delete", "@Patch", "@Head", "@Options",
	"@All", "@MessagePattern", "@EventPattern", "@GrpcMethod",
	"@Subscription", "@ResolveField", "@Query(", "@Mutation(",
}

// nuxtHandlerNames are function names that Nuxt server routes use as entry points.
var nuxtHandlerNames = []string{
	"defineEventHandler", "eventHandler", "defineLazyEventHandler",
}

// astroHTTPExports are the exported function names that Astro API routes treat as handlers.
var astroHTTPExports = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "ALL": true, "prerender": true,
}

// FindEntryPoints returns SymbolIDs of functions/methods that are entry points.
//
// Detection strategies (in priority order):
//  1. NestJS HTTP decorators (@Get, @Post, ...)
//  2. SvelteKit +server.ts HTTP method exports (GET, POST, ...)
//  3. Remix loader/action exports
//  4. Next.js lifecycle exports
//  5. Nuxt defineEventHandler exports
//  6. Express/Hono/Fastify route handler — function name registered via app.get/post/...
//  7. Exported functions with route-handler-like names
//  8. Convention: function named "main"
//
//nolint:gocognit,gocyclo // entry point detection checks many framework patterns
func (e *Extractor) FindEntryPoints(symbols []*treesitter.Symbol, _ string) []treesitter.SymbolID {
	var eps []treesitter.SymbolID

	for _, sym := range symbols {
		if sym == nil {
			continue
		}
		if sym.Kind != treesitter.SymbolFunction && sym.Kind != treesitter.SymbolMethod {
			continue
		}

		// 1. NestJS decorators
		decs, hasDecs := e.decorators[sym.ID]
		if hasDecs && isNestJSHandler(decs) {
			eps = append(eps, sym.ID)
			continue
		}

		// 2. SvelteKit HTTP method exports
		if isSvelteKitFile(sym.File) && svelteKitHTTPExports[sym.Name] {
			eps = append(eps, sym.ID)
			continue
		}

		// 2a. Astro API routes (src/pages/ directory with exported HTTP handlers)
		if isAstroAPIFile(sym.File) && astroHTTPExports[sym.Name] && e.exported[sym.ID] {
			eps = append(eps, sym.ID)
			continue
		}

		// 3. Remix exports (file in app/routes/ directory)
		if isRemixRouteFile(sym.File) && remixExports[sym.Name] {
			eps = append(eps, sym.ID)
			continue
		}

		// 4. Next.js lifecycle exports
		if nextjsExports[sym.Name] {
			eps = append(eps, sym.ID)
			continue
		}

		// 5. Nuxt defineEventHandler exports
		if isNuxtHandler(sym.Name) && e.exported[sym.ID] {
			eps = append(eps, sym.ID)
			continue
		}

		// 6. Registered as a route handler via app.get/post/use/...
		if e.routeHandlers[sym.Name] {
			eps = append(eps, sym.ID)
			continue
		}

		// 7. Exported functions with route-handler-like names
		if e.exported[sym.ID] && isLikelyRouteHandler(sym.Name) {
			eps = append(eps, sym.ID)
			continue
		}

		// 8. Convention: main
		if sym.Name == "main" {
			eps = append(eps, sym.ID)
			continue
		}
	}

	return eps
}

// isNestJSHandler returns true if any of the decorators is a NestJS HTTP handler decorator.
func isNestJSHandler(decs []string) bool {
	for _, dec := range decs {
		trimmed := strings.TrimSpace(dec)
		for _, pattern := range nestjsHTTPDecorators {
			if strings.HasPrefix(trimmed, pattern) {
				return true
			}
		}
	}
	return false
}

// isSvelteKitFile returns true if the file name matches the SvelteKit server route convention.
func isSvelteKitFile(file string) bool {
	base := filepath.Base(file)
	// +server.ts, +server.js, +page.server.ts, +page.server.js
	return strings.HasPrefix(base, "+server.") || strings.HasSuffix(base, ".server.ts") || strings.HasSuffix(base, ".server.js")
}

// isRemixRouteFile returns true if the file is in a Remix routes directory.
func isRemixRouteFile(file string) bool {
	return strings.Contains(file, "/routes/") || strings.Contains(file, "/app/routes")
}

// isNuxtHandler returns true if the function name is a Nuxt event handler factory.
func isNuxtHandler(name string) bool {
	for _, h := range nuxtHandlerNames {
		if name == h {
			return true
		}
	}
	return false
}

// isAstroAPIFile returns true if the file is an Astro API route (in src/pages/).
func isAstroAPIFile(file string) bool {
	return strings.Contains(file, "src/pages/")
}

// isLikelyRouteHandler returns true if the symbol name looks like an HTTP route handler.
// This is a heuristic for Express/Fastify/Hono where handlers are named functions.
func isLikelyRouteHandler(name string) bool {
	lower := strings.ToLower(name)
	// Contains "handler", "controller", "route", "endpoint", "action" in name
	keywords := []string{"handler", "controller", "route", "endpoint", "action", "middleware"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	// Looks like an HTTP method handler: getUser, postItem, deleteOrder
	for method := range httpMethods {
		if strings.HasPrefix(lower, method) && len(name) > len(method) {
			return true
		}
	}
	return false
}
