package com.mt.security.controller;

import com.mt.security.dto.AuthResponse;
import com.mt.security.dto.LoginRequest;
import com.mt.security.dto.RegisterRequest;
import com.mt.security.service.AuthService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public String register( @Valid @RequestBody RegisterRequest request ) {
        authService.register(request);
        return "User registered successfully";
    }

    @PostMapping("/login")
    public AuthResponse login( @Valid @RequestBody LoginRequest request ) {
        return authService.login(request);
    }
}