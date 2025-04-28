package com.autentication.dto;

import com.autentication.validation.EmailValido;
import jakarta.validation.constraints.NotBlank;

public record LoginDTO(@EmailValido String email, @NotBlank(message = "A senha nao pode estar vazia") String password) {

}
