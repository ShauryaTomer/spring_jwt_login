package com.jwt_security.controllers;

import com.jwt_security.dto.LoginResponseDto;
import com.jwt_security.dto.RegistrationDto;
import com.jwt_security.models.ApplicationUser;
import com.jwt_security.repository.UserRepository;
import com.jwt_security.services.AuthenticationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*") //to make sure we don't get blocked by some cors issue
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;
    public AuthenticationController(AuthenticationService authenticationService, UserRepository userRepository) {
        this.authenticationService = authenticationService;
        this.userRepository = userRepository;
    }

    @GetMapping("/register")
    //TODO: Instead of returning ApplicationUser return just a ResponseEntity because returning even encrypted password is bad.
    public ApplicationUser registerUser(@RequestBody RegistrationDto body) {
//        if(userRepository.findByUsername(body.getUsername())) {
//            return new ResponseEntity<>("username is already taken!!", HttpStatus.BAD_REQUEST);
//        }

        return authenticationService.registerUser(body.getUsername(), body.getPassword());
    }

    @PostMapping("/login")
    public LoginResponseDto loginUser(@RequestBody RegistrationDto body) {
        return authenticationService.loginUser(body.getUsername(), body.getPassword());
    }
}
