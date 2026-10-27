package com.mt.security.dto;

public record AuthResponse(
        String accessToken,
        String tokenType
) {}
