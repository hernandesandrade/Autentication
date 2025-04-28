package com.autentication.dto;

import com.autentication.validation.EmailValido;

public record EmailDTO(@EmailValido String email) {
}
