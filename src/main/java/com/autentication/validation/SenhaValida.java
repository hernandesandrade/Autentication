package com.autentication.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = SenhaValidaValidation.class)
@Target({ ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface SenhaValida {
    String message() default "Mínimo de 8 caracteres, 1 maiúscula, 1 minúscula, 1 número e 1 caractere especial";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
