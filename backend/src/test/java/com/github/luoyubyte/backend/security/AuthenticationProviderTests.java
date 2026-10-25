package com.github.luoyubyte.backend.security;

import com.github.luoyubyte.backend.config.SecurityConfig;
import com.github.luoyubyte.backend.entity.SysUser;
import com.github.luoyubyte.backend.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthenticationProviderTests {

    private static final String EMPLOYEE_NO = "TEST_AUTH_001";
    private static final String PASSWORD = "TestOnly_Password_123!";

    private final UserMapper userMapper = mock(UserMapper.class);
    private final SecurityConfig config = new SecurityConfig();
    private final PasswordEncoder encoder = config.passwordEncoder();

    private final DaoAuthenticationProvider provider =
            config.authenticationProvider(
                    new DatabaseUserDetailsService(userMapper),
                    encoder
            );

    @Test
    void shouldAuthenticateCorrectPassword() {
        prepareAccount("ACTIVE");

        Authentication result = provider.authenticate(
                loginRequest(PASSWORD)
        );

        assertTrue(result.isAuthenticated());
        assertEquals(EMPLOYEE_NO, result.getName());
    }

    @Test
    void shouldRejectWrongPassword() {
        prepareAccount("ACTIVE");

        assertThrows(
                BadCredentialsException.class,
                () -> provider.authenticate(loginRequest("WrongPassword!"))
        );
    }

    @Test
    void shouldRejectDisabledAccount() {
        prepareAccount("DISABLED");

        assertThrows(
                DisabledException.class,
                () -> provider.authenticate(loginRequest(PASSWORD))
        );
    }

    @Test
    void shouldRejectMissingAccount() {
        when(userMapper.findByEmployeeNo(EMPLOYEE_NO))
                .thenReturn(null);

        assertThrows(
                BadCredentialsException.class,
                () -> provider.authenticate(loginRequest(PASSWORD))
        );
    }

    private void prepareAccount(String status) {
        SysUser account = new SysUser();
        account.setEmployeeNo(EMPLOYEE_NO);
        account.setPasswordHash(encoder.encode(PASSWORD));
        account.setRole("EMPLOYEE");
        account.setStatus(status);
        account.setMustChangePassword(true);

        when(userMapper.findByEmployeeNo(EMPLOYEE_NO))
                .thenReturn(account);
    }

    private UsernamePasswordAuthenticationToken loginRequest(
            String password) {

        return UsernamePasswordAuthenticationToken.unauthenticated(
                EMPLOYEE_NO,
                password
        );
    }
}