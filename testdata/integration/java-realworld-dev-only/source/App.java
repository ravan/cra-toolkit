package com.example;
import org.springframework.web.bind.annotation.*;
@RestController
public class App {
    @GetMapping("/")
    public String index() { return "OK"; }
}
