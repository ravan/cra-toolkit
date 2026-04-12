package com.example;

import com.google.gson.Gson;

public class GsonWrapper {
    private static final Gson Gson = new Gson();

    public static Object deserialize(String json, Class<?> clazz) {
        return Gson.fromJson(json, clazz);
    }
}
