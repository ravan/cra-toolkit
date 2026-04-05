// Copyright 2026 Ravan Naidoo
// SPDX-License-Identifier: GPL-3.0-only

package java_test

import (
	"testing"

	"github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter"
	javaextractor "github.com/ravan/suse-cra-toolkit/pkg/vex/reachability/treesitter/java"
)

// TestFindEntryPoints_MainMethod verifies that public static void main is an entry point.
func TestFindEntryPoints_MainMethod(t *testing.T) {
	source := `package com.example;

public class App {
    public static void main(String[] args) {
        System.out.println("Hello");
    }

    private void helper() {}
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("App.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	var foundMain bool
	for _, ep := range eps {
		if string(ep) == "com.example.App.main" {
			foundMain = true
		}
	}

	if !foundMain {
		t.Errorf("expected 'com.example.App.main' to be an entry point, got: %v", eps)
	}
}

// TestFindEntryPoints_SpringRestController verifies that Spring @GetMapping and @PostMapping
// annotated methods are detected as entry points.
//
//nolint:gocognit,gocyclo // test validates multiple Spring annotation patterns
func TestFindEntryPoints_SpringRestController(t *testing.T) {
	source := `package com.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/users")
    public List<User> listUsers() {
        return new ArrayList<>();
    }

    @PostMapping("/users")
    public User createUser(User user) {
        return user;
    }

    private void internalHelper() {}
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("UserController.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (Spring route handlers), got %d", len(eps))
		for _, ep := range eps {
			t.Logf("  entry point: %s", ep)
		}
	}

	// internalHelper should NOT be an entry point
	for _, ep := range eps {
		if string(ep) == "com.example.UserController.internalHelper" {
			t.Error("'internalHelper' should not be an entry point")
		}
	}
}

// TestFindEntryPoints_Scheduled verifies that @Scheduled annotated methods are entry points.
func TestFindEntryPoints_Scheduled(t *testing.T) {
	source := `package com.example;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class ScheduledTask {

    @Scheduled(fixedRate = 5000)
    public void reportCurrentTime() {
        System.out.println("Tick");
    }

    private void setup() {}
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("ScheduledTask.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	var foundScheduled bool
	for _, ep := range eps {
		if string(ep) == "com.example.ScheduledTask.reportCurrentTime" {
			foundScheduled = true
		}
	}

	if !foundScheduled {
		t.Errorf("expected 'reportCurrentTime' to be entry point due to @Scheduled, got: %v", eps)
	}
}

// TestFindEntryPoints_JUnitTest verifies that @Test annotated methods are detected as entry points.
func TestFindEntryPoints_JUnitTest(t *testing.T) {
	source := `package com.example;

import org.junit.jupiter.api.Test;

public class AppTest {

    @Test
    public void testMain() {
        // test body
    }

    @Test
    public void testProcess() {
        // test body
    }

    private void helperAssertion() {}
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("AppTest.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (@Test methods), got %d: %v", len(eps), eps)
	}

	// helperAssertion should NOT be an entry point
	for _, ep := range eps {
		if string(ep) == "com.example.AppTest.helperAssertion" {
			t.Error("'helperAssertion' should not be an entry point")
		}
	}
}

// TestFindEntryPoints_NoEntryPoints verifies that plain helper methods are not entry points.
func TestFindEntryPoints_NoEntryPoints(t *testing.T) {
	symbols := []*treesitter.Symbol{
		{
			ID:   "com.example.Utils.formatDate",
			Name: "formatDate",
			Kind: treesitter.SymbolMethod,
			File: "Utils.java",
		},
		{
			ID:   "com.example.Utils.parseDate",
			Name: "parseDate",
			Kind: treesitter.SymbolMethod,
			File: "Utils.java",
		},
	}

	ext := javaextractor.New()
	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) != 0 {
		t.Errorf("expected no entry points for plain helper methods, got %d: %v", len(eps), eps)
	}
}

// TestFindEntryPoints_SpringDeleteAndPutMappings verifies @DeleteMapping and @PutMapping.
func TestFindEntryPoints_SpringDeleteAndPutMappings(t *testing.T) {
	source := `package com.example;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ItemController {

    @PutMapping("/items/{id}")
    public Item updateItem(Long id, Item item) {
        return item;
    }

    @DeleteMapping("/items/{id}")
    public void deleteItem(Long id) {}
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("ItemController.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 2 {
		t.Errorf("expected at least 2 entry points (@PutMapping, @DeleteMapping), got %d: %v", len(eps), eps)
	}
}

// TestFindEntryPoints_MainOnlyPublicStatic verifies that only public static main is an entry point.
// A class with no public static main() must produce no main-based entry points.
// The positive case (public static main IS detected) is covered by TestFindEntryPoints_MainMethod.
func TestFindEntryPoints_MainOnlyPublicStatic(t *testing.T) {
	// Source with only non-qualifying "main" methods: private and instance-only.
	// Neither should be classified as an entry point.
	source := `package com.example;

public class App {
    private void main() {
        // private helper — NOT an entry point
    }

    public void main(int x) {
        // public but NOT static — NOT an entry point
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("App.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	// Neither private nor non-static main should be an entry point
	for _, ep := range eps {
		if string(ep) == "com.example.App.main" {
			t.Errorf("'com.example.App.main' (private/non-static overloads) must not be an entry point, got: %v", eps)
			break
		}
	}

	if len(eps) != 0 {
		t.Errorf("expected 0 entry points for non-qualifying main overloads, got %d: %v", len(eps), eps)
	}
}

// TestFindEntryPoints_JAXRS verifies that JAX-RS @GET and @POST annotated methods are entry points.
func TestFindEntryPoints_JAXRS(t *testing.T) {
	source := `package com.example;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;

@Path("/api")
public class ApiResource {
    @GET
    @Path("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }

    @POST
    @Path("/users")
    public Response createUser(User user) {
        return Response.ok(userService.create(user)).build();
    }

    private void internalHelper() {
        // not an entry point
    }
}
`
	tree, src := parseSource(t, source)
	defer tree.Close()

	ext := javaextractor.New()
	symbols, err := ext.ExtractSymbols("ApiResource.java", src, tree)
	if err != nil {
		t.Fatalf("ExtractSymbols: %v", err)
	}

	eps := ext.FindEntryPoints(symbols, "/project")

	if len(eps) < 2 {
		t.Errorf("expected at least 2 JAX-RS entry points (@GET, @POST), got %d: %v", len(eps), eps)
	}

	var foundGet, foundPost bool
	for _, ep := range eps {
		switch string(ep) {
		case "com.example.ApiResource.getUsers":
			foundGet = true
		case "com.example.ApiResource.createUser":
			foundPost = true
		}
	}

	if !foundGet {
		t.Errorf("expected 'getUsers' (@GET) to be an entry point, entry points: %v", eps)
	}
	if !foundPost {
		t.Errorf("expected 'createUser' (@POST) to be an entry point, entry points: %v", eps)
	}

	// internalHelper must NOT be an entry point
	for _, ep := range eps {
		if string(ep) == "com.example.ApiResource.internalHelper" {
			t.Error("'internalHelper' must not be an entry point")
		}
	}
}
