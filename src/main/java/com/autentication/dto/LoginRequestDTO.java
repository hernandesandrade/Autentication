package com.autentication.dto;

import com.autentication.models.User;

public record LoginRequestDTO(String email, String password) {

}
