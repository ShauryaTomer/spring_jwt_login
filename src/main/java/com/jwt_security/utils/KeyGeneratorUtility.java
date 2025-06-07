package com.jwt_security.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyGeneratorUtility {

    public static KeyPair generateRsaKey() {

        KeyPair keyPair;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); //The KeyPairGenerator class is used to generate pairs of public and private keys. Key generators are constructed using the getInstance factory methods (static methods that return instances of a given class)
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch(Exception e) {
            throw new IllegalStateException();
        }
        return keyPair;
    }
}
