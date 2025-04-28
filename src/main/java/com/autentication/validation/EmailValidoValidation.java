package com.autentication.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class EmailValidoValidation implements ConstraintValidator<EmailValido, String> {

    private final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
    private final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

    @Override
    public boolean isValid(String email, ConstraintValidatorContext context) {
        if (email == null || email.isEmpty()) {
            enviarErro("O email não pode estar vazio", context);
            return false;
        }
        return EMAIL_PATTERN.matcher(email).matches();
    }

    private void enviarErro(String erro, ConstraintValidatorContext context){
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(erro)
                .addConstraintViolation();
    }
}
