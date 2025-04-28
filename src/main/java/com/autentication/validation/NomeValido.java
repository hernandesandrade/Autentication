package com.autentication.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = NomeValidoValidation.class)
@Target({ ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface NomeValido {
    String message() default "Formato de nome inválido.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}