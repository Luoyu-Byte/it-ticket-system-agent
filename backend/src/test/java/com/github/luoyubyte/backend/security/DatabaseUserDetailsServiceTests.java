package com.github.luoyubyte.backend.security;

import com.github.luoyubyte.backend.entity.SysUser;
import com.github.luoyubyte.backend.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DatabaseUserDetailsServiceTests {

    private final UserMapper userMapper = mock(UserMapper.class);

    private final DatabaseUserDetailsService service =
            new DatabaseUserDetailsService(userMapper);

    @ParameterizedTest
    @ValueSource(strings = {"EMPLOYEE", "ENGINEER", "ADMIN"})
    void shouldLoadActiveUserWithRole(String role) {
        SysUser account = createAccount(role, "ACTIVE");
        account.setMustChangePassword(true);

        when(userMapper.findByEmployeeNo("TEST_AUTH_001"))
                .thenReturn(account);

        UserDetails result = service.loadUserByUsername("TEST_AUTH_001");

        assertEquals("TEST_AUTH_001", result.getUsername());
        assertEquals("TEST_ONLY_HASH", result.getPassword());
        assertTrue(result.isEnabled());
        assertEquals(1, result.getAuthorities().size());
        assertTrue(result.getAuthorities().stream()
                .anyMatch(authority ->
                        authority.getAuthority().equals("ROLE_" + role)));
    }

    @Test
    void shouldMarkDisabledUserAsNotEnabled() {
        SysUser account = createAccount("EMPLOYEE", "DISABLED");

        when(userMapper.findByEmployeeNo("TEST_AUTH_001"))
                .thenReturn(account);

        UserDetails result = service.loadUserByUsername("TEST_AUTH_001");

        assertFalse(result.isEnabled());
    }

    @Test
    void shouldRejectMissingUser() {
        when(userMapper.findByEmployeeNo("NOT_EXISTS"))
                .thenReturn(null);

        assertThrows(
                UsernameNotFoundException.class,
                () -> service.loadUserByUsername("NOT_EXISTS")
        );
    }

    private SysUser createAccount(String role, String status) {
        SysUser account = new SysUser();
        account.setEmployeeNo("TEST_AUTH_001");
        account.setPasswordHash("TEST_ONLY_HASH");
        account.setRole(role);
        account.setStatus(status);
        return account;
    }
}