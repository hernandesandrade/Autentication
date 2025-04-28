package com.autentication.dto;

import com.autentication.validation.SenhaValida;
import jakarta.validation.constraints.NotBlank;

public record PasswordDTO(@SenhaValida String password, @NotBlank(message = "A senha não pode estar vazia") String confirmPassword) {
}
