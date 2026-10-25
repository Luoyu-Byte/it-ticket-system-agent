package com.github.luoyubyte.backend.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

class PasswordEncoderTests {

    private final PasswordEncoder passwordEncoder =
            new SecurityConfig().passwordEncoder();

    @Test
    void shouldEncodeAndVerifyPassword() {
        String password = "TestOnly_Password_123!";
        String encoded = passwordEncoder.encode(password);

        assertNotEquals(password, encoded);
        assertTrue(encoded.startsWith("{bcrypt}"));
        assertTrue(passwordEncoder.matches(password, encoded));
        assertFalse(passwordEncoder.matches("Wrong_Password_123!", encoded));
    }

    @Test
    void shouldProduceDifferentHashesForSamePassword() {
        String password = "TestOnly_Password_123!";

        String first = passwordEncoder.encode(password);
        String second = passwordEncoder.encode(password);

        assertNotEquals(first, second);
        assertTrue(passwordEncoder.matches(password, first));
        assertTrue(passwordEncoder.matches(password, second));
    }
}