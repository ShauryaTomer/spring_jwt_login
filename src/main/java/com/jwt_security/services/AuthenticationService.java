package com.jwt_security.services;

import com.jwt_security.dto.LoginResponseDto;
import com.jwt_security.models.ApplicationUser;
import com.jwt_security.models.Role;
import com.jwt_security.repository.RoleRepository;
import com.jwt_security.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@Transactional //treat every operation that happens here as a transaction
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authenticationManager; //will determine weather or not we not to create a new jwt token, this will the same instance as the one inside our configuration manager
    private final TokenService tokenService;

    public AuthenticationService(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder encoder, AuthenticationManager authenticationManager, TokenService tokenService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }

    public ApplicationUser registerUser(String username, String password) {
        String encodedPassword = encoder.encode(password);
        Role userRole = roleRepository.findByAuthority("USER").get();

        Set<Role> roles = new HashSet<>();
        roles.add(userRole);

        return userRepository.save(ApplicationUser.builder()
                        .username(username)
                        .password(encodedPassword)
                        .authorities(roles)
                .build());
    }

    public LoginResponseDto loginUser(String username, String password) {
        try{
            Authentication auth = authenticationManager.authenticate( //whenever we send in request for login a user, it'll pass username and password to this authentication manager, it'll use our UserDetailsService to grab that user, and it's password from database. Then check the password, if everything is correct it'll give us this new token auth.
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            String token = tokenService.generateJwt(auth);

            return new LoginResponseDto(token);

        }catch(AuthenticationException e) {
            return new LoginResponseDto("");
        }
    }
}
