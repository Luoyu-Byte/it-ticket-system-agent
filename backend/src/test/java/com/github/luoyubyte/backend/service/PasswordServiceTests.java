package com.github.luoyubyte.backend.service;

import com.github.luoyubyte.backend.config.SecurityConfig;
import com.github.luoyubyte.backend.dto.ChangePasswordRequest;
import com.github.luoyubyte.backend.entity.SysUser;
import com.github.luoyubyte.backend.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

// 只模拟数据库访问，使用真实业务逻辑及密码编码器，不连接真实数据库。
class PasswordServiceTests {

    private static final String EMPLOYEE_NO = "TEST_PASSWORD_001";
    private static final String OLD_PASSWORD = "Original_Password_123!";
    private static final String NEW_PASSWORD = "Changed_Password_456!";

    private final UserMapper userMapper = mock(UserMapper.class);
    private final PasswordEncoder encoder = new SecurityConfig().passwordEncoder();
    private final PasswordService service = new PasswordService(userMapper, encoder);

    private SysUser prepareAccount() {
        SysUser account = new SysUser();
        account.setId(100L);
        account.setEmployeeNo(EMPLOYEE_NO);
        account.setStatus("ACTIVE");
        account.setMustChangePassword(true);
        account.setPasswordHash(encoder.encode(OLD_PASSWORD));
        when(userMapper.findByEmployeeNo(EMPLOYEE_NO)).thenReturn(account);
        return account;
    }

    @ParameterizedTest
    @MethodSource("validNewPasswords")
    void shouldUpdateUsingHashWithoutChangingPasswordText(String newPassword) {
        SysUser account = prepareAccount();

        // 校验更新参数：数据库只能收到新哈希，原哈希作为并发保护条件传入。
        when(userMapper.updatePassword(eq(100L), eq(account.getPasswordHash()), anyString()))
                .thenAnswer(invocation -> {
                    String hash = invocation.getArgument(2);
                    assertNotEquals(newPassword, hash);
                    assertTrue(hash.startsWith("{bcrypt}"));
                    assertTrue(encoder.matches(newPassword, hash));
                    assertFalse(encoder.matches(OLD_PASSWORD, hash));
                    return 1;
                });

        assertDoesNotThrow(() -> service.changePassword(
                EMPLOYEE_NO, new ChangePasswordRequest(OLD_PASSWORD, newPassword)));
        verify(userMapper).updatePassword(eq(100L), eq(account.getPasswordHash()), anyString());
    }

    static Stream<String> validNewPasswords() {
        // ASCII 15字符下限、72字节上限；中文及补充平面字符按UTF-8计数。
        // 带首尾空格的密码也必须原样编码，不得偷偷 trim。
        return Stream.of(
                "a".repeat(15), "b".repeat(72),
                "中".repeat(15), "中".repeat(24),
                "😀".repeat(18), "  New password with spaces  "
        );
    }

    @ParameterizedTest
    @MethodSource("invalidRequests")
    void shouldRejectInvalidInputBeforeDatabaseAccess(ChangePasswordRequest request) {
        assertStatus(HttpStatus.BAD_REQUEST, request);
        verifyNoInteractions(userMapper);
    }

    static Stream<ChangePasswordRequest> invalidRequests() {
        return Stream.of(
                null,
                new ChangePasswordRequest(null, NEW_PASSWORD),
                new ChangePasswordRequest(" ", NEW_PASSWORD),
                new ChangePasswordRequest(OLD_PASSWORD, null),
                new ChangePasswordRequest(OLD_PASSWORD, ""),
                new ChangePasswordRequest(OLD_PASSWORD, " ".repeat(15)),
                new ChangePasswordRequest("a".repeat(73), NEW_PASSWORD),
                new ChangePasswordRequest(OLD_PASSWORD, "a".repeat(14)),
                new ChangePasswordRequest(OLD_PASSWORD, "b".repeat(73)),
                new ChangePasswordRequest(OLD_PASSWORD, "中".repeat(25)),
                new ChangePasswordRequest(OLD_PASSWORD, "😀".repeat(19)),
                new ChangePasswordRequest(OLD_PASSWORD, "😀".repeat(8))
        );
    }

    @Test
    void shouldRejectMissingAccountWithoutUpdate() {
        assertStatus(HttpStatus.UNAUTHORIZED,
                new ChangePasswordRequest(OLD_PASSWORD, NEW_PASSWORD));
        verifyNoUpdate();
    }

    @Test
    void shouldRejectDisabledAccountWithoutUpdate() {
        prepareAccount().setStatus("DISABLED");
        assertStatus(HttpStatus.UNAUTHORIZED,
                new ChangePasswordRequest(OLD_PASSWORD, NEW_PASSWORD));
        verifyNoUpdate();
    }

    @Test
    void shouldRejectWrongOriginalPasswordWithoutUpdate() {
        prepareAccount();
        assertStatus(HttpStatus.BAD_REQUEST,
                new ChangePasswordRequest("WrongPassword!", NEW_PASSWORD));
        verifyNoUpdate();
    }

    @Test
    void shouldRejectUnchangedPasswordWithoutUpdate() {
        prepareAccount();
        assertStatus(HttpStatus.BAD_REQUEST,
                new ChangePasswordRequest(OLD_PASSWORD, OLD_PASSWORD));
        verifyNoUpdate();
    }

    @Test
    void shouldRejectConcurrentChangeWithoutRetryingUpdate() {
        SysUser account = prepareAccount();
        when(userMapper.updatePassword(eq(100L), eq(account.getPasswordHash()), anyString()))
                .thenReturn(0);

        // 模拟条件更新失败，不能忽略结果或改用无条件更新覆盖密码。
        assertStatus(HttpStatus.CONFLICT,
                new ChangePasswordRequest(OLD_PASSWORD, NEW_PASSWORD));
        verify(userMapper, times(1))
                .updatePassword(eq(100L), eq(account.getPasswordHash()), anyString());
    }

    @Test
    void shouldNotExposePasswordsInRequestToString() {
        String text = new ChangePasswordRequest(OLD_PASSWORD, NEW_PASSWORD).toString();
        assertFalse(text.contains(OLD_PASSWORD));
        assertFalse(text.contains(NEW_PASSWORD));
    }

    private void assertStatus(HttpStatus status, ChangePasswordRequest request) {
        ResponseStatusException exception = assertThrows(ResponseStatusException.class,
                () -> service.changePassword(EMPLOYEE_NO, request));
        assertEquals(status, exception.getStatusCode());
    }

    private void verifyNoUpdate() {
        verify(userMapper, never()).updatePassword(any(), any(), any());
    }
}
