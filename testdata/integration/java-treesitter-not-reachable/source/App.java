package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    // Logger imported but only used for debug, not info
    private static final Logger logger = LogManager.getLogger(App.class);

    public String process(String input) {
        // Only uses System.out, not logger.info
        System.out.println("Processing: " + input);
        return input.toUpperCase();
    }
}
