package com.example;
import org.springframework.web.bind.annotation.*;
@RestController
public class App {
    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        System.out.println("Request: " + name);
        return "Hello " + name;
    }
}
