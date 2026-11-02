package com.github.luoyubyte.backend.service;

import com.github.luoyubyte.backend.config.SecurityConfig;
import com.github.luoyubyte.backend.entity.SysUser;
import com.github.luoyubyte.backend.mapper.UserMapper;
import com.github.luoyubyte.backend.security.TemporaryPasswordGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

// 模拟数据库及临时密码来源，使用真实业务层和密码编码器。
// 不创建真实管理员，不输出临时密码或密码哈希。
class InitialAdminServiceTests {

    private static final String TEST_PASSWORD = "TestOnly_Initial_123456!";

    private final UserMapper userMapper = mock(UserMapper.class);
    private final TemporaryPasswordGenerator generator = mock(TemporaryPasswordGenerator.class);
    private final PasswordEncoder encoder = new SecurityConfig().passwordEncoder();
    private final InitialAdminService service = new InitialAdminService(userMapper, encoder, generator);

    private void prepareSuccessfulInsert() {
        when(generator.generate()).thenReturn(TEST_PASSWORD);
        when(userMapper.insertInitialAdmin(anyString(), anyString(), anyString())).thenReturn(1);
    }

    @ParameterizedTest
    @MethodSource("validNames")
    void shouldCreateAdminWithHashAndReturnOneTimeCredentials(String name) {
        prepareSuccessfulInsert();

        InitialAdminService.InitialAdminCredentials result = service.initialize(name);

        ArgumentCaptor<String> savedHash = ArgumentCaptor.forClass(String.class);
        verify(userMapper).insertInitialAdmin(eq("INIT_ADMIN"), eq(name.strip()), savedHash.capture());
        assertTrue(savedHash.getValue().startsWith("{bcrypt}"));
        assertNotEquals(TEST_PASSWORD, savedHash.getValue());
        assertTrue(encoder.matches(TEST_PASSWORD, savedHash.getValue()));
        assertEquals("INIT_ADMIN", result.employeeNo());
        assertEquals(TEST_PASSWORD, result.temporaryPassword());
        verify(generator, times(1)).generate();
    }

    static Stream<String> validNames() {
        // 包含首尾空白处理、50码点边界及补充平面字符的长度计算。
        return Stream.of("管理员", "  初始化管理员  ", "中".repeat(50), "😀".repeat(50));
    }

    @ParameterizedTest
    @MethodSource("invalidNames")
    void shouldRejectInvalidNameBeforeDatabaseAccess(String name) {
        assertThrows(IllegalArgumentException.class, () -> service.initialize(name));
        verifyNoInteractions(userMapper, generator);
    }

    static Stream<String> invalidNames() {
        return Stream.of(null, "", " ", "\t\n", "a".repeat(51), "😀".repeat(51));
    }

    @ParameterizedTest
    @ValueSource(longs = {1, 2})
    void shouldRejectInitializationWhenAnyAdminExists(long count) {
        // Mapper 的统计不筛选ACTIVE；业务层不能在管理员停用后重新初始化。
        when(userMapper.countAdmins()).thenReturn(count);

        assertThrows(IllegalStateException.class, () -> service.initialize("管理员"));

        verify(userMapper).countAdmins();
        verifyNoMoreInteractions(userMapper);
        verifyNoInteractions(generator);
    }

    @Test
    void shouldNotOverwriteEmployeeOccupyingInitialNumber() {
        SysUser employee = new SysUser();
        employee.setEmployeeNo("INIT_ADMIN");
        employee.setRole("EMPLOYEE");
        when(userMapper.findByEmployeeNo("INIT_ADMIN")).thenReturn(employee);

        assertThrows(IllegalStateException.class, () -> service.initialize("管理员"));

        verify(userMapper, never()).insertInitialAdmin(any(), any(), any());
        verifyNoInteractions(generator);
        assertEquals("EMPLOYEE", employee.getRole());
    }

    @Test
    void shouldRejectDuplicateInsertWithoutRetryOrCredentialReturn() {
        when(generator.generate()).thenReturn(TEST_PASSWORD);
        when(userMapper.insertInitialAdmin(anyString(), anyString(), anyString()))
                .thenThrow(new DuplicateKeyException("模拟并发工号冲突"));

        // 模拟数据库唯一约束拒绝并发插入，不冒充真实多进程/数据库并发测试。
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> service.initialize("管理员"));

        verify(userMapper, times(1)).insertInitialAdmin(eq("INIT_ADMIN"), anyString(), anyString());
        assertFalse(failure.getMessage().contains(TEST_PASSWORD));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 2})
    void shouldRejectUnexpectedAffectedRows(int rows) {
        when(generator.generate()).thenReturn(TEST_PASSWORD);
        when(userMapper.insertInitialAdmin(anyString(), anyString(), anyString())).thenReturn(rows);

        assertThrows(IllegalStateException.class, () -> service.initialize("管理员"));
    }

    @Test
    void shouldNotCreateOrGeneratePasswordAgainOnSecondInitialization() {
        prepareSuccessfulInsert();
        when(userMapper.countAdmins()).thenReturn(0L, 1L);

        service.initialize("第一个管理员");
        assertThrows(IllegalStateException.class, () -> service.initialize("重复初始化"));

        verify(generator, times(1)).generate();
        verify(userMapper, times(1)).insertInitialAdmin(eq("INIT_ADMIN"), eq("第一个管理员"), anyString());
    }

    @Test
    void shouldPropagateDatabaseFailureWithoutReportingSuccess() {
        when(generator.generate()).thenReturn(TEST_PASSWORD);
        when(userMapper.insertInitialAdmin(anyString(), anyString(), anyString()))
                .thenThrow(new DataAccessResourceFailureException("模拟数据库不可用"));

        assertThrows(DataAccessResourceFailureException.class, () -> service.initialize("管理员"));
        verify(userMapper, times(1)).insertInitialAdmin(anyString(), anyString(), anyString());
    }

    @Test
    void shouldHideCredentialInResultToString() {
        var result = new InitialAdminService.InitialAdminCredentials("INIT_ADMIN", TEST_PASSWORD);
        assertFalse(result.toString().contains(TEST_PASSWORD));
        assertTrue(result.toString().contains("PROTECTED"));
    }

    @Test
    void shouldDiscoverAndWireGeneratorAndServiceWithoutInitializingAccount() {
        // 小型Spring上下文验证@Component/@Service扫描与构造注入，避免只测new对象。
        try (var context = new AnnotationConfigApplicationContext()) {
            context.registerBean(UserMapper.class, () -> userMapper);
            context.registerBean(PasswordEncoder.class, () -> encoder);
            context.scan("com.github.luoyubyte.backend.service", "com.github.luoyubyte.backend.security");
            context.refresh();

            assertNotNull(context.getBean(TemporaryPasswordGenerator.class));
            assertNotNull(context.getBean(InitialAdminService.class));
            verifyNoInteractions(userMapper);
        }
    }
}
