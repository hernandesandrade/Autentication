package com.autentication.infra.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptService {

    private final Cache<String, Integer> attemptsCache;

    public LoginAttemptService() {
        this.attemptsCache = Caffeine.newBuilder()
                .expireAfterWrite(15, TimeUnit.MINUTES)
                .maximumSize(1000)
                .build();
    }

    public void loginFailed(String username) {
        int attempts = attemptsCache.getIfPresent(username) != null
                ? attemptsCache.getIfPresent(username)
                : 0;
        attempts++;
        attemptsCache.put(username, attempts);
    }

    public void loginSucceeded(String username) {
        attemptsCache.invalidate(username);
    }

    public boolean shouldShowRecaptcha(String username) {
        Integer attempts = attemptsCache.getIfPresent(username);
        return attempts != null && attempts >= 3;
    }
}

