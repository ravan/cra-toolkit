package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.*;

@RestController
public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    @GetMapping("/api/search")
    public String search(@RequestParam String query) {
        logger.info("Search query: {}", query);
        return "Results for: " + query;
    }
}
