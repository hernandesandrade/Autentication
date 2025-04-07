package com.autentication.exceptions;

public class AuthenticationBusinessException extends RuntimeException {
    public AuthenticationBusinessException(String message) {
        super(message);
    }
}
