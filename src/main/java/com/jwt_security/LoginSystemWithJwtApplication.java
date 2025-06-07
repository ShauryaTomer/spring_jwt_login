package com.jwt_security;

import com.jwt_security.models.ApplicationUser;
import com.jwt_security.models.Role;
import com.jwt_security.repository.RoleRepository;
import com.jwt_security.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class LoginSystemWithJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(LoginSystemWithJwtApplication.class, args);

    }

    @Bean
    CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder encoder) {
        return agrs -> {
            if(roleRepository.findByAuthority("ADMIN").isPresent()) return; //makes sure script runs only first time when database in empty

            Role adminRole = roleRepository.save(Role.builder().authority("ADMIN").build());
            roleRepository.save(Role.builder().authority("USER").build());

            Set<Role> roles = new HashSet<>();
            roles.add(adminRole);
            userRepository.save(ApplicationUser.builder()
                            .username("admin")
                            .password(encoder.encode("password"))
                            .authorities(roles)
                    .build());
        };
    }

}
