package com.autentication.infra.security;

import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {
    private final int MAX_ATTEMPTS = 3;
    private Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();

    public void loginFailed(String key) {
        int attempts = attemptsCache.getOrDefault(key, 0);
        attemptsCache.put(key, attempts + 1);
    }

    public void loginSucceeded(String key) {
        attemptsCache.remove(key);
    }

    public boolean isBlocked(String key) {
        return attemptsCache.getOrDefault(key, 0) >= MAX_ATTEMPTS;
    }

    public int getAttempts(String key) {
        return attemptsCache.getOrDefault(key, 0);
    }
}