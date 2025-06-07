package com.jwt_security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor

public class LoginResponseDto {
    private String jwt;
}
