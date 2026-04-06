package com.example;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
public class AppTest {
    private static final Logger log = LogManager.getLogger(AppTest.class);
    public void testEndpoint() {
        System.out.println("Testing endpoint via stdout");
    }
}
