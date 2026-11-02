package com.github.luoyubyte.backend.security;

import com.github.luoyubyte.backend.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

// 不输出生成的临时密码，不连接数据库；只检查当前生成器的行为。
class TemporaryPasswordGeneratorTests {

    private final TemporaryPasswordGenerator generator = new TemporaryPasswordGenerator();

    @Test
    void shouldGenerate24AsciiCharactersFrom18Bytes() {
        String password = generator.generate();

        assertEquals(24, password.length());
        assertEquals(24, password.getBytes(StandardCharsets.UTF_8).length);
        assertTrue(password.matches("[A-Za-z0-9_-]{24}"));
        assertEquals(18, Base64.getUrlDecoder().decode(password).length);
    }

    @Test
    void shouldNotReturnConstantPasswordInSample() {
        Set<String> passwords = new HashSet<>();

        // 检查是否误写成固定密码或固定随机种子，不把样本无重复当成数学保证。
        for (int i = 0; i < 100; i++) {
            assertTrue(passwords.add(generator.generate()), "生成器样本出现重复");
        }
    }

    @Test
    void shouldWorkWithExistingPasswordEncoder() {
        PasswordEncoder encoder = new SecurityConfig().passwordEncoder();
        String password = generator.generate();
        String hash = encoder.encode(password);

        assertTrue(hash.startsWith("{bcrypt}"));
        assertTrue(encoder.matches(password, hash));
        assertFalse(encoder.matches(password + "x", hash));
    }
}
