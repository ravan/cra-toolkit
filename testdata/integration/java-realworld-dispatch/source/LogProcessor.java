package com.example;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
public class LogProcessor implements Processor {
    private static final Logger logger = LogManager.getLogger(LogProcessor.class);
    public String process(String data) {
        logger.info("Processing: {}", data);
        return "done: " + data;
    }
}
