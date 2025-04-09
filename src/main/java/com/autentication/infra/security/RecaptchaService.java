package com.autentication.infra.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.file.AccessDeniedException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RecaptchaService {

    //LINK DO SITE RECAPTCHA: https://www.google.com/recaptcha/admin/site/721880510?hl=pt-br

    private final int MAX_ATTEMPTS = 1;
    public Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();

    @Value("${recaptcha.secret-key}")
    private String secretKey;

    @Value("${recaptcha.verify-url}")
    private String RECAPTCHA_VERIFY_URL;

    public boolean verify(String recaptchaResponse) throws AccessDeniedException {
        if (recaptchaResponse == null || recaptchaResponse.trim().isEmpty()){
            throw new AccessDeniedException("Marque a caixa 'Eu não sou um robô'");
        }
        RestTemplate restTemplate = new RestTemplate();
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.put("secret", Collections.singletonList(secretKey));
        params.put("response", Collections.singletonList(recaptchaResponse));

        Map response = restTemplate.postForObject(RECAPTCHA_VERIFY_URL, params, Map.class);
        if (response == null) {
            throw new AccessDeniedException("O servidor reCAPTCHA retornou response vazio");
        }
        if (response.containsKey("error-codes")){
            throw new AccessDeniedException(response.get("error-codes").toString());
        }
        return (Boolean) response.get("success");
    }

    public void loginFailed(String key) {
        int attempts = attemptsCache.getOrDefault(key, 0);
        attemptsCache.put(key, attempts + 1);
    }

    public void loginSucceeded(String key) {
        attemptsCache.remove(key);
    }

    public boolean isPresent(String key) {
        return attemptsCache.getOrDefault(key, 0) >= MAX_ATTEMPTS;
    }

    public int getErros(String key) {
        return attemptsCache.getOrDefault(key, 0);
    }
}
