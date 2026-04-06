package com.example;
import org.springframework.web.bind.annotation.*;
@RestController
public class App {
    private final Processor processor = new LogProcessor();
    @GetMapping("/process")
    public String process(@RequestParam String data) {
        return processor.process(data);
    }
}
