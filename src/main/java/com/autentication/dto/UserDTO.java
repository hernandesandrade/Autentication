package com.autentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class UserDTO {

    @NotNull(message = "Campo vazio")
    @NotBlank(message = "Campo em branco")
    private String name;

    @NotNull(message = "Campo vazio")
    @NotBlank(message = "Campo em branco")
    @Email(message = "Email invalido..")
    private String email;

    public @NotNull(message = "Campo vazio") @NotBlank(message = "Campo em branco") String getName() {
        return name;
    }

    public void setName(@NotNull(message = "Campo vazio") @NotBlank(message = "Campo em branco") String name) {
        this.name = name;
    }

    public @NotNull(message = "Campo vazio") @NotBlank(message = "Campo em branco") @Email(message = "Email invalido..") String getEmail() {
        return email;
    }

    public void setEmail(@NotNull(message = "Campo vazio") @NotBlank(message = "Campo em branco") @Email(message = "Email invalido..") String email) {
        this.email = email;
    }
}
