package com.autentication.infra.security;

import com.autentication.exceptions.RecaptchaException;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
public class RecaptchaService {

    //LINK DO SITE RECAPTCHA: https://www.google.com/recaptcha/admin/site/721880510?hl=pt-br

    final int MAX_ATTEMPTS = 3;
    private final Cache<String, Integer> attemptsCache;

    @Value("${recaptcha.secret-key}")
    private String secretKey;

    @Value("${recaptcha.verify-url}")
    private String RECAPTCHA_VERIFY_URL;

    public RecaptchaService() {
        this.attemptsCache = Caffeine.newBuilder()
                .expireAfterWrite(15, TimeUnit.MINUTES)
                .maximumSize(1000)
                .build();
    }

    public boolean verify(String recaptchaResponse) throws RecaptchaException {
        if (recaptchaResponse == null || recaptchaResponse.trim().isEmpty()){
            throw new RecaptchaException("Marque a caixa 'Eu não sou um robô'");
        }
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.put("secret", Collections.singletonList(secretKey));
        params.put("response", Collections.singletonList(recaptchaResponse));

        Map response = restTemplate.postForObject(RECAPTCHA_VERIFY_URL, params, Map.class);
        if (response == null) {
            throw new RecaptchaException("O servidor reCAPTCHA retornou response vazio");
        }
        if (response.containsKey("error-codes")){
            throw new RecaptchaException(response.get("error-codes").toString());
        }
        return (Boolean) response.get("success");
    }

    public void loginFailed(HttpServletRequest request, String email) {
        int attempts = Optional.ofNullable(attemptsCache.getIfPresent(email + "::" + getClientIp(request))).orElse(0) + 1;
        attemptsCache.put(email + "::" + getClientIp(request), attempts);
    }

    public void loginSucceeded(HttpServletRequest request, String email) {
        attemptsCache.invalidate(email + "::" + getClientIp(request));
    }

    public boolean isPresent(HttpServletRequest request, String email) {
        Integer attempts = attemptsCache.getIfPresent(email + "::" + getClientIp(request));
        return attempts != null && attempts >= MAX_ATTEMPTS;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

}
