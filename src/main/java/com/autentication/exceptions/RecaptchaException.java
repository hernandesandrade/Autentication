package com.autentication.exceptions;

public class RecaptchaException extends RuntimeException {
    public RecaptchaException(String message) {
        super(message);
    }
}
