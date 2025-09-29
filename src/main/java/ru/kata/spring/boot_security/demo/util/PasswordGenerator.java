package ru.kata.spring.boot_security.demo.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordGenerator {

    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public static String encode(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }
}