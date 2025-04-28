package com.autentication.dto;

import com.autentication.validation.EmailValido;

public record LoginDTO(@EmailValido String email, String password) {

}
