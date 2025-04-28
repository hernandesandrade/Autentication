package com.autentication.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class NomeValidoValidation implements ConstraintValidator<NomeValido, String> {

    private void enviarErro(String erro, ConstraintValidatorContext context){
        context.disableDefaultConstraintViolation();
        context.buildConstraintViolationWithTemplate(erro)
                .addConstraintViolation();
    }

    @Override
    public boolean isValid(String nome, ConstraintValidatorContext context) {
        if (nome == null || nome.trim().isEmpty()) {
            enviarErro("O nome não pode estar vazio", context);
            return false;
        }

        String nomeTrim = nome.trim();

        if (nomeTrim.length() < 2 || nomeTrim.length() > 100) {
            enviarErro("O nome deve ter entre 2 e 100 caracteres", context);
            return false;
        }

        if (!nomeTrim.matches("^[\\p{L} .'-]+$")) {
            enviarErro("O nome deve conter apenas letras, espaços, pontos, apóstrofos ou hífens", context);
            return false;
        }

        if (nomeTrim.matches("^[ -].*|.*[ -]$")) {
            enviarErro("O nome não pode começar/terminar com espaço ou hífen", context);
            return false;
        }

        if (nomeTrim.contains("  ") || nomeTrim.contains("--") || nomeTrim.contains("'-") || nomeTrim.contains("-'")) {
            enviarErro("O nome não pode ter múltiplos espaços/hífens consecutivos", context);
            return false;
        }

        if (nomeTrim.split(" ").length < 2){
            enviarErro("Digite pelo menos um sobrenome", context);
            return false;
        }

        return true;
    }
}
