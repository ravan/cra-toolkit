package com.example;
import org.springframework.web.bind.annotation.*;
@RestController
public class App {
    private final SearchService service = new SearchService();
    @GetMapping("/search")
    public String search(@RequestParam String query) {
        return service.search(query);
    }
}
