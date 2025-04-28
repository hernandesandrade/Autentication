package com.autentication.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class SenhaValidaValidation implements ConstraintValidator<SenhaValida, String> {
    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isEmpty()) {
            enviarErro("A senha não pode estar vazia", context);
            return false;
        }
        String regex = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";
        return password.matches(regex);
    }

    private void enviarErro(String erro, ConstraintValidatorContext context){
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(erro)
                .addConstraintViolation();
    }


//    boolean isValid = true;
//
//    // Verifica o comprimento mínimo de 8 caracteres
//        if (password.length() < 8) {
//        isValid = false;
//        enviarErro("Deve ter pelo menos 8 caracteres.", context);
//    }
//
//    // Verifica se contém pelo menos uma letra maiúscula
//        if (!password.matches(".*[A-Z].*")) {
//        isValid = false;
//        enviarErro("Deve conter pelo menos uma letra maiúscula.", context);
//    }
//
//    // Verifica se contém pelo menos uma letra minúscula
//        if (!password.matches(".*[a-z].*")) {
//        isValid = false;
//        enviarErro("Deve conter pelo menos uma letra minúscula.", context);
//    }
//
//    // Verifica se contém pelo menos um número
//        if (!password.matches(".*\\d.*")) {
//        isValid = false;
//        enviarErro("Deve conter pelo menos um número.", context);
//    }
//
//    // Verifica se contém pelo menos um caractere especial (qualquer símbolo não alfanumérico)
//        if (!password.matches(".*[^A-Za-z0-9].*")) {
//        isValid = false;
//        enviarErro("Deve conter pelo menos um caractere especial.", context);
//    }
//
//    // Verifica se não contém espaços em branco
//        if (password.matches(".*\\s.*")) {
//        isValid = false;
//        enviarErro("Não pode conter espaços em branco.", context);
//    }
//        return isValid;
}
