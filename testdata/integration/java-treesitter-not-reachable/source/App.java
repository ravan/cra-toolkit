package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.*;

@RestController
public class App {
    private static final Logger logger = LogManager.getLogger(App.class);

    @GetMapping("/api/process")
    public String process(@RequestParam String input) {
        // Uses System.out instead of logger.info — logger.info not reachable
        System.out.println("Processing: " + input);
        return input.toUpperCase();
    }
}
