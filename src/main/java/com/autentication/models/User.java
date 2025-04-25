package com.autentication.models;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;
    private String name;
    @Column(unique = true)
    private String email;
    private String password;
    private String role = "USER";
    @Column(nullable = false)
    private boolean ativo;
    private String tokenConfirmacaoEmail;
    private LocalDateTime tokenConfirmacaoEmailExpires;
    private String tokenResetPassword;
    private LocalDateTime tokenResetPasswordExpires;

    public User(){}

    public User(String name, String email, String password, String role) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = role;
    }

    @Override
    public String toString() {
        return "User{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", password='" + password + '\'' +
                ", role='" + role + '\'' +
                '}';
    }

    public String getTokenConfirmacaoEmail() {
        return tokenConfirmacaoEmail;
    }

    public void setTokenConfirmacaoEmail(String tokenConfirmacaoEmail) {
        this.tokenConfirmacaoEmail = tokenConfirmacaoEmail;
    }

    public LocalDateTime getTokenConfirmacaoEmailExpires() {
        return tokenConfirmacaoEmailExpires;
    }

    public void setTokenConfirmacaoEmailExpires(LocalDateTime tokenConfirmacaoEmailExpires) {
        this.tokenConfirmacaoEmailExpires = tokenConfirmacaoEmailExpires;
    }

    public String getTokenResetPassword() {
        return tokenResetPassword;
    }

    public void setTokenResetPassword(String tokenResetPassword) {
        this.tokenResetPassword = tokenResetPassword;
    }

    public LocalDateTime getTokenResetPasswordExpires() {
        return tokenResetPasswordExpires;
    }

    public void setTokenResetPasswordExpires(LocalDateTime tokenResetPasswordExpires) {
        this.tokenResetPasswordExpires = tokenResetPasswordExpires;
    }

    public boolean isAtivo() {
        return ativo;
    }

    public void setAtivo(boolean ativo) {
        this.ativo = ativo;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public String getRole() {
        return role;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setRole(String role) {
        this.role = role;
    }
}