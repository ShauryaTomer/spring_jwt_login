package com.jwt_security.dto;

import lombok.Data;
import lombok.NonNull;

@Data
public class RegistrationDto {

    private String username;
    private String password;
}
