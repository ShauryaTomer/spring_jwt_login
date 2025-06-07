package com.jwt_security.controllers;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
@CrossOrigin("*") //allow any requesting url to receive url from this, in production should be more secure so configure accordingly
public class UserController {

    @GetMapping("/")
    public String helloUserController() {
        return "User access level";
    }
}
