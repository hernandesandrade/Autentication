package com.autentication.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = EmailValidoValidation.class)
@Target({ ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface EmailValido {
    String message() default "Formato de email inválido.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}