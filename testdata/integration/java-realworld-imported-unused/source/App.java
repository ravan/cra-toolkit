package com.example;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.*;
@RestController
public class App {
    private static final Logger logger = LogManager.getLogger(App.class);
    @GetMapping("/health")
    public String health() {
        System.out.println("Health check");
        return "OK";
    }
}
