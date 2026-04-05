package java

import (
	"strings"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
)

// entryPointAnnotations are all annotations that mark a method as an entry point.
// This includes Spring HTTP handlers, scheduled tasks, and JUnit test methods.
var entryPointAnnotations = []string{
	// Spring MVC/WebFlux HTTP handlers
	"@GetMapping",
	"@PostMapping",
	"@PutMapping",
	"@DeleteMapping",
	"@PatchMapping",
	"@RequestMapping",
	// Spring Scheduling
	"@Scheduled",
	// Spring Event Listeners
	"@EventListener",
	"@KafkaListener",
	"@RabbitListener",
	"@SqsListener",
	// JUnit 4 & 5 test annotations
	"@Test",
	"@RepeatedTest",
	"@ParameterizedTest",
	"@TestFactory",
	// Spring Boot lifecycle
	"@PostConstruct",
	"@PreDestroy",
	// JAX-RS HTTP methods
	"@GET",
	"@POST",
	"@PUT",
	"@DELETE",
	"@PATCH",
	"@HEAD",
	"@OPTIONS",
}

// isEntryPointAnnotation returns true if the annotation text matches any known entry point annotation.
func isEntryPointAnnotation(ann string) bool {
	// Normalize: annotations collected include the "@" prefix and may include arguments.
	// E.g. "@GetMapping" or "@Scheduled(fixedRate = 5000)"
	name := ann
	if idx := strings.IndexByte(ann, '('); idx > 0 {
		name = ann[:idx]
	}
	name = strings.TrimSpace(name)

	for _, pattern := range entryPointAnnotations {
		if name == pattern {
			return true
		}
	}
	return false
}

// isMainMethod returns true if the symbol is a proper Java application entry point.
// Requires: method named "main" AND declared with both "public" and "static" modifiers.
// This prevents false positives from private or instance-only "main" helper methods.
func (e *Extractor) isMainMethod(sym *treesitter.Symbol) bool {
	return sym.Name == "main" && e.publicStaticMethods[sym.ID]
}

// FindEntryPoints returns SymbolIDs of methods that are application entry points.
//
// Detection strategies:
//  1. public static void main — standard Java application entry point
//  2. Spring @GetMapping / @PostMapping / @PutMapping / @DeleteMapping / @PatchMapping / @RequestMapping
//  3. Spring @Scheduled — scheduled task methods
//  4. Spring @EventListener / @KafkaListener / @RabbitListener — event-driven handlers
//  5. JUnit @Test / @RepeatedTest / @ParameterizedTest — test entry points
//  6. JAX-RS @GET / @POST / @PUT / @DELETE / @PATCH / @HEAD / @OPTIONS
//  7. Spring @PostConstruct / @PreDestroy lifecycle hooks
//
//nolint:gocognit,gocyclo // entry point detection checks many annotation patterns
func (e *Extractor) FindEntryPoints(symbols []*treesitter.Symbol, _ string) []treesitter.SymbolID {
	var eps []treesitter.SymbolID

	for _, sym := range symbols {
		if sym == nil {
			continue
		}
		if sym.Kind != treesitter.SymbolMethod {
			continue
		}

		// 1. main method
		if e.isMainMethod(sym) {
			eps = append(eps, sym.ID)
			continue
		}

		// 2–7. Annotation-based entry points
		anns, hasAnns := e.annotations[sym.ID]
		if !hasAnns {
			continue
		}
		for _, ann := range anns {
			if isEntryPointAnnotation(ann) {
				eps = append(eps, sym.ID)
				break
			}
		}
	}

	return eps
}
