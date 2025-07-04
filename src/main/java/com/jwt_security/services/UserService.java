package com.jwt_security.services;

import com.jwt_security.models.ApplicationUser;
import com.jwt_security.models.Role;
import com.jwt_security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        System.out.println("In the user details service"); //called a tracing print, because it traces when application enters this method.

        return userRepository.findByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException("No User found with this username"));
    }
}
