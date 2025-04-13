package com.autentication.utils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class NomeValidator {

    // Lista de preposições/artigos que devem ficar em minúsculo
    private static final List<String> PALAVRAS_MINUSCULAS = Arrays.asList(
            "da", "de", "do", "das", "dos", "e", "a", "o", "em", "na", "no", "nas", "nos"
    );

    /**
     * Formata o nome corretamente segundo as convenções da língua portuguesa.
     * - Primeira letra de cada nome em maiúscula
     * - Preposições/artigos em minúsculo
     * - Trata casos especiais como "Mc", "O'", "D'", etc.
     *
     * @param nome O nome a ser formatado
     * @return O nome formatado ou null se o input for null
     */
    public static String formatarNome(String nome) {
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

    /**
     * Validação mais completa para cadastro
     */
    public static boolean validarNome(String nome) {
        if (nome == null || nome.trim().isEmpty()) {
            return false;
        }

        String nomeTrim = nome.trim();

        // Valida comprimento (2-100 caracteres)
        if (nomeTrim.length() < 2 || nomeTrim.length() > 100) {
            return false;
        }

        // Valida caracteres (permite letras, espaços, hífens e apóstrofos)
        if (!nomeTrim.matches("^[\\p{L} .'-]+$")) {
            return false;
        }

        // Valida que não começa/termina com espaço/hífen
        if (nomeTrim.matches("^[ -].*|.*[ -]$")) {
            return false;
        }

        // Valida que não tem múltiplos espaços/hífens consecutivos
        if (nomeTrim.contains("  ") || nomeTrim.contains("--") || nomeTrim.contains("'-") || nomeTrim.contains("-'")) {
            return false;
        }

        // Valida que tem pelo menos um nome e um sobrenome
        return nomeTrim.split(" ").length >= 2;
    }

}
