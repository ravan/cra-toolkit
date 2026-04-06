package com.example;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
public class SearchService {
    private static final Logger logger = LogManager.getLogger(SearchService.class);
    public String search(String query) {
        logger.info("Searching: {}", query);
        return "Results for: " + query;
    }
}
