package com.autentication.utils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class UserNameFormatter {

    // Lista de preposições/artigos que devem ficar em minúsculo
    private static final List<String> PALAVRAS_MINUSCULAS = Arrays.asList(
            "da", "de", "do", "das", "dos", "e", "a", "o", "em", "na", "no", "nas", "nos"
    );

    public static String formatar(String nome) {
        if (nome == null) return null;

        nome = nome.trim().replaceAll("\\s+", " ");
        if (nome.isEmpty()) return nome;

        // Trata casos como "McDonald", "O'Connor", "D'Angelo"
        nome = nome.replaceAll("(?i)\\b(mc|o'|d'|mac)([a-z])", "$1$2".toLowerCase());

        String[] partes = nome.split(" ");

        List<String> partesFormatadas = Arrays.stream(partes)
                .map(parte -> {
                    if (parte.isEmpty()) return parte;

                    // Mantém preposições/artigos em minúsculo (exceto se for a primeira palavra)
                    if (PALAVRAS_MINUSCULAS.contains(parte.toLowerCase()) && !parte.equals(partes[0])) {
                        return parte.toLowerCase();
                    }

                    // Capitaliza a primeira letra e mantém o resto em minúsculo
                    return parte.substring(0, 1).toUpperCase() +
                            parte.substring(1).toLowerCase();
                })
                .collect(Collectors.toList());

        return String.join(" ", partesFormatadas);
    }

}
