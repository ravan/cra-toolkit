package com.example;

public class App {
    public static void main(String[] args) {
        String json = args.length > 0 ? args[0] : "{}";
        Object result = GsonWrapper.deserialize(json, Object.class);
        System.out.println(result);
    }
}
