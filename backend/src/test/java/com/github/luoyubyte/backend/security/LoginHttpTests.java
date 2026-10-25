package com.github.luoyubyte.backend.security;

import com.github.luoyubyte.backend.config.SecurityConfig;
import com.github.luoyubyte.backend.controller.AuthController;
import com.github.luoyubyte.backend.controller.HelloController;
import com.github.luoyubyte.backend.entity.SysUser;
import com.github.luoyubyte.backend.mapper.UserMapper;
import com.github.luoyubyte.backend.service.PasswordService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// 加载 Web 层和实际安全配置，不加载数据库连接。
// 模拟的只有 Mapper，账号转换、密码校验、登录处理均使用真实实现。
@WebMvcTest({AuthController.class, HelloController.class})
@Import({SecurityConfig.class, DatabaseUserDetailsService.class, PasswordService.class})
class LoginHttpTests {

    private static final String EMPLOYEE_NO = "TEST_LOGIN_001";
    private static final String PASSWORD = "TestOnly_Password_123!";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private SessionRegistry sessionRegistry;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserMapper userMapper;

    private SysUser account;

    @BeforeEach
    void prepareAccount() {
        // MockMvc 不触发完整的容器会话生命周期，主动隔离测试间的登记数据。
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            for (SessionInformation session : sessionRegistry.getAllSessions(principal, true)) {
                sessionRegistry.removeSessionInformation(session.getSessionId());
            }
        }

        // 每个测试准备独立的模拟账号；不向数据库插入记录。
        account = new SysUser();
        account.setEmployeeNo(EMPLOYEE_NO);
        account.setPasswordHash(passwordEncoder.encode(PASSWORD));
        account.setRole("EMPLOYEE");
        account.setStatus("ACTIVE");
        account.setMustChangePassword(false);

        when(userMapper.findByEmployeeNo(EMPLOYEE_NO))
                .thenReturn(account);
        // 为当前用户响应准备完整的模拟资料。
        account.setId(100L);
        account.setName("登录测试员工");
    }

    @Test
    void shouldLoginAndKeepSession() throws Exception {
        // 携带有效 CSRF 令牌，提交约定的表单字段。
        MvcResult result = mvc.perform(post("/api/auth/login")
                        .with(csrf().asHeader())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("employeeNo", EMPLOYEE_NO)
                        .param("password", PASSWORD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.employeeNo").value(EMPLOYEE_NO))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andReturn();

        // 复用登录后的 Session 请求受保护接口。
        // 这验证登录身份保存在会话中，而非只返回了一次“成功”。
        MockHttpSession session =
                (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(session);

        mvc.perform(get("/api/hello").session(session))
                .andExpect(status().isOk());
    }

    @Test
    void shouldRejectWrongPassword() throws Exception {
        // CSRF 正确，但密码错误，应进入统一认证失败处理。
        mvc.perform(post("/api/auth/login")
                        .with(csrf().asHeader())
                        .param("employeeNo", EMPLOYEE_NO)
                        .param("password", "WrongPassword!"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("工号或密码错误"));
    }

    @Test
    void shouldRejectDisabledAccount() throws Exception {
        // 密码正确也不能登录停用账号；对外保持相同失败提示。
        account.setStatus("DISABLED");

        mvc.perform(post("/api/auth/login")
                        .with(csrf().asHeader())
                        .param("employeeNo", EMPLOYEE_NO)
                        .param("password", PASSWORD))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").value("工号或密码错误"));
    }

    @Test
    void shouldRejectLoginWithoutCsrf() throws Exception {
        // 没有 CSRF 令牌时，应在查询账号之前拒绝请求。
        mvc.perform(post("/api/auth/login")
                        .param("employeeNo", EMPLOYEE_NO)
                        .param("password", PASSWORD))
                .andExpect(status().isForbidden());

        verifyNoInteractions(userMapper);
    }

    @Test
    void shouldRejectAnonymousAccess() throws Exception {
        // 没有登录会话时，受保护接口仍然返回 401。
        mvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized());
    }
    // 通过真实登录流程取得 Session，供后续请求复用。
    private MockHttpSession loginAndGetSession() throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login")
                        .with(csrf().asHeader())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("employeeNo", EMPLOYEE_NO)
                        .param("password", PASSWORD))
                .andExpect(status().isOk())
                .andReturn();

        MockHttpSession session =
                (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(session);
        return session;
    }

    @Test
    void shouldReturnCurrentUserWithoutPassword() throws Exception {
        MockHttpSession session = loginAndGetSession();

        // 即使请求参数传入其他工号，也必须返回会话中的当前用户。
        mvc.perform(get("/api/auth/me")
                        .session(session)
                        .param("employeeNo", "OTHER_USER"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(100))
                .andExpect(jsonPath("$.employeeNo").value(EMPLOYEE_NO))
                .andExpect(jsonPath("$.name").value("登录测试员工"))
                .andExpect(jsonPath("$.role").value("EMPLOYEE"))
                .andExpect(jsonPath("$.mustChangePassword").value(false))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void shouldRejectAnonymousMeRequest() throws Exception {
        // 当前用户接口不能在未登录时读取。
        mvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectMeWhenAccountDisabledAfterLogin() throws Exception {
        MockHttpSession session = loginAndGetSession();

        // 模拟登录后账号被停用；接口应检查最新状态。
        account.setStatus("DISABLED");

        mvc.perform(get("/api/auth/me").session(session))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldReturnPasswordChangeRequirement() throws Exception {
        // 必须改密的账号仍可验证身份，并读取改密标记。
        account.setMustChangePassword(true);
        MockHttpSession session = loginAndGetSession();

        // 明确模拟 Servlet 路径，让过滤器能正确匹配 /me 白名单。
        mvc.perform(get("/api/auth/me").servletPath("/api/auth/me")
                .session(session)).andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(true));
    }

    @Test
    void shouldBlockBusinessAccessWhenPasswordChangeRequired() throws Exception {
        account.setMustChangePassword(true);
        MockHttpSession session = loginAndGetSession();

        // 必须改密时可以登录，但不能访问普通业务接口。
        mvc.perform(get("/api/hello")
                        .servletPath("/api/hello")
                        .session(session))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("PASSWORD_CHANGE_REQUIRED"));

        // 拒绝业务访问不应注销身份，用户仍需读取资料并完成改密。
        mvc.perform(get("/api/auth/me")
                        .servletPath("/api/auth/me")
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(true));
    }

    @Test
    void shouldInvalidateSessionWhenAccountDisabled() throws Exception {
        MockHttpSession session = loginAndGetSession();

        // 模拟登录后被管理员停用，旧会话不能继续访问业务。
        account.setStatus("DISABLED");

        mvc.perform(get("/api/hello")
                        .servletPath("/api/hello")
                        .session(session))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SESSION_INVALID"));

        // 不仅返回错误，还必须真正销毁当前会话。
        assertTrue(session.isInvalid());
    }

    @Test
    void shouldInvalidateSessionWhenAccountMissing() throws Exception {
        MockHttpSession session = loginAndGetSession();

        // 模拟账号查不到的异常边界，不代表业务提供删除账号功能。
        when(userMapper.findByEmployeeNo(EMPLOYEE_NO)).thenReturn(null);

        mvc.perform(get("/api/hello")
                        .servletPath("/api/hello")
                        .session(session))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SESSION_INVALID"));

        assertTrue(session.isInvalid());
    }

    @Test
    void shouldLogoutAndInvalidateCurrentSession() throws Exception {
        MockHttpSession session = loginAndGetSession();
        String oldSessionId = session.getId();

        // 有效 CSRF 令牌允许退出；只返回 204，并通知浏览器删除 Cookie。
        mvc.perform(post("/api/auth/logout")
                        .session(session)
                        .with(csrf().asHeader()))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""))
                .andExpect(header().doesNotExist("Location"))
                .andExpect(cookie().maxAge("JSESSIONID", 0));

        assertTrue(session.isInvalid());

        // MockMvc 不运行真实容器的 Cookie→Session 查找。
        // 上面单独确认服务器会话已失效；这里确认旧 Cookie 本身不能提供登录身份。
        mvc.perform(get("/api/hello")
                        .cookie(new Cookie("JSESSIONID", oldSessionId)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectLogoutWithoutCsrfAndKeepSession() throws Exception {
        MockHttpSession session = loginAndGetSession();

        // 缺少 CSRF 令牌应拒绝退出，而不是悄悄注销用户。
        mvc.perform(post("/api/auth/logout").session(session))
                .andExpect(status().isForbidden());

        mvc.perform(get("/api/auth/me")
                        .servletPath("/api/auth/me")
                        .session(session))
                .andExpect(status().isOk());
    }

    @Test
    void shouldAllowLogoutWhenPasswordChangeRequired() throws Exception {
        account.setMustChangePassword(true);
        MockHttpSession session = loginAndGetSession();

        // 强制改密不应阻止用户主动退出。
        mvc.perform(post("/api/auth/logout")
                        .servletPath("/api/auth/logout")
                        .session(session)
                        .with(csrf().asHeader()))
                .andExpect(status().isNoContent());

        assertTrue(session.isInvalid());
    }

    @Test
    void shouldKeepOtherSessionWhenCurrentSessionLogsOut() throws Exception {
        MockHttpSession currentSession = loginAndGetSession();
        MockHttpSession otherSession = loginAndGetSession();

        // 同一账号分别登录两次，退出其中一个会话不影响另一个。
        mvc.perform(post("/api/auth/logout")
                        .session(currentSession)
                        .with(csrf().asHeader()))
                .andExpect(status().isNoContent());

        assertTrue(currentSession.isInvalid());
        mvc.perform(get("/api/hello").session(otherSession))
                .andExpect(status().isOk());
    }

    @Test
    void shouldRegisterMultipleSessionsForSameAccount() throws Exception {
        MockHttpSession first = loginAndGetSession();
        MockHttpSession second = loginAndGetSession();

        // 登记必须由实际登录流程完成，而不是测试手工往登记表塞数据。
        SessionInformation firstInfo = sessionRegistry.getSessionInformation(first.getId());
        SessionInformation secondInfo = sessionRegistry.getSessionInformation(second.getId());
        assertNotNull(firstInfo);
        assertNotNull(secondInfo);
        UserDetails principal = assertInstanceOf(UserDetails.class, firstInfo.getPrincipal());
        assertEquals(EMPLOYEE_NO, principal.getUsername());
        assertEquals(2, sessionRegistry.getAllSessions(principal, false).size());
        assertFalse(firstInfo.isExpired());
        assertFalse(secondInfo.isExpired());

        // maximumSessions(-1) 允许两个会话同时正常使用。
        mvc.perform(get("/api/hello").session(first)).andExpect(status().isOk());
        mvc.perform(get("/api/hello").session(second)).andExpect(status().isOk());
    }

    @Test
    void shouldRejectAndInvalidateSessionsMarkedExpired() throws Exception {
        MockHttpSession first = loginAndGetSession();
        MockHttpSession second = loginAndGetSession();
        SessionInformation firstInfo = sessionRegistry.getSessionInformation(first.getId());
        assertNotNull(firstInfo);

        // 模拟后续改密成功后的处理：把该账号的所有已登记会话标记失效。
        for (SessionInformation info : sessionRegistry.getAllSessions(firstInfo.getPrincipal(), false)) {
            info.expireNow();
        }

        // 不要求浏览器主动退出；旧会话下一次请求就被框架拒绝并注销。
        for (MockHttpSession session : new MockHttpSession[]{first, second}) {
            mvc.perform(get("/api/hello").session(session))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("SESSION_INVALID"))
                    .andExpect(header().doesNotExist("Location"));
            assertTrue(session.isInvalid());
        }
    }

    @Test
    void shouldChangePasswordAndExpireOnlyCurrentAccountsSessions() throws Exception {
        String newPassword = "Changed_Password_456!";
        account.setMustChangePassword(true);
        String previousHash = account.getPasswordHash();
        MockHttpSession current = loginAndGetSession();
        MockHttpSession other = loginAndGetSession();

        // 准备另一个真实走登录流程的模拟账号，确认不会被误改密码或误退出。
        SysUser unrelated = new SysUser();
        unrelated.setId(200L);
        unrelated.setEmployeeNo("OTHER_EMPLOYEE");
        unrelated.setPasswordHash(passwordEncoder.encode(PASSWORD));
        unrelated.setRole("EMPLOYEE");
        unrelated.setStatus("ACTIVE");
        unrelated.setMustChangePassword(false);
        when(userMapper.findByEmployeeNo("OTHER_EMPLOYEE")).thenReturn(unrelated);
        MvcResult unrelatedLogin = mvc.perform(post("/api/auth/login")
                        .with(csrf().asHeader())
                        .param("employeeNo", "OTHER_EMPLOYEE")
                        .param("password", PASSWORD))
                .andExpect(status().isOk()).andReturn();
        MockHttpSession unrelatedSession =
                (MockHttpSession) unrelatedLogin.getRequest().getSession(false);
        assertNotNull(unrelatedSession);

        // 只模拟 SQL 成功后的数据变化，密码校验及编码使用真实 Service。
        when(userMapper.updatePassword(eq(100L), eq(previousHash), anyString()))
                .thenAnswer(invocation -> {
                    String newHash = invocation.getArgument(2);
                    assertTrue(passwordEncoder.matches(newPassword, newHash));
                    account.setPasswordHash(newHash);
                    account.setMustChangePassword(false);
                    return 1;
                });

        // 即使 query 参数伪造其他工号，也只能修改当前登录账号。
        mvc.perform(post("/api/auth/change-password")
                        .servletPath("/api/auth/change-password")
                        .session(current).with(csrf().asHeader())
                        .param("employeeNo", "OTHER_EMPLOYEE")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordChangeBody(PASSWORD, newPassword)))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""))
                .andExpect(cookie().maxAge("JSESSIONID", 0));

        assertTrue(current.isInvalid());
        mvc.perform(get("/api/hello").session(other))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("SESSION_INVALID"));
        assertTrue(other.isInvalid());
        mvc.perform(get("/api/hello").session(unrelatedSession))
                .andExpect(status().isOk());
        verify(userMapper).updatePassword(eq(100L), eq(previousHash), anyString());
        verify(userMapper, never()).updatePassword(eq(200L), anyString(), anyString());

        // 模拟更新后旧密码无法重新登录，新密码可登录且解除强制改密。
        mvc.perform(post("/api/auth/login").with(csrf().asHeader())
                        .param("employeeNo", EMPLOYEE_NO).param("password", PASSWORD))
                .andExpect(status().isUnauthorized());
        MvcResult newLogin = mvc.perform(post("/api/auth/login").with(csrf().asHeader())
                        .param("employeeNo", EMPLOYEE_NO).param("password", newPassword))
                .andExpect(status().isOk()).andReturn();
        MockHttpSession newSession = (MockHttpSession) newLogin.getRequest().getSession(false);
        assertNotNull(newSession);
        mvc.perform(get("/api/auth/me").servletPath("/api/auth/me").session(newSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mustChangePassword").value(false));
        mvc.perform(get("/api/hello").session(newSession)).andExpect(status().isOk());
    }

    @Test
    void shouldKeepSessionsWhenOriginalPasswordIsWrong() throws Exception {
        MockHttpSession current = loginAndGetSession();
        MockHttpSession other = loginAndGetSession();

        mvc.perform(post("/api/auth/change-password")
                        .servletPath("/api/auth/change-password")
                        .session(current).with(csrf().asHeader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordChangeBody("WrongPassword!", "Changed_Password_456!")))
                .andExpect(status().isBadRequest());

        verify(userMapper, never()).updatePassword(any(), any(), any());
        mvc.perform(get("/api/hello").session(current)).andExpect(status().isOk());
        mvc.perform(get("/api/hello").session(other)).andExpect(status().isOk());
    }

    @Test
    void shouldNotExpireSessionsWhenPasswordUpdateConflicts() throws Exception {
        MockHttpSession session = loginAndGetSession();
        when(userMapper.updatePassword(any(), any(), any())).thenReturn(0);

        mvc.perform(post("/api/auth/change-password")
                        .servletPath("/api/auth/change-password")
                        .session(session).with(csrf().asHeader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordChangeBody(PASSWORD, "Changed_Password_456!")))
                .andExpect(status().isConflict());

        mvc.perform(get("/api/hello").session(session)).andExpect(status().isOk());
    }

    @Test
    void shouldRejectPasswordChangeWithoutCsrf() throws Exception {
        MockHttpSession session = loginAndGetSession();
        clearInvocations(userMapper);

        mvc.perform(post("/api/auth/change-password")
                        .servletPath("/api/auth/change-password")
                        .session(session).contentType(MediaType.APPLICATION_JSON)
                        .content(passwordChangeBody(PASSWORD, "Changed_Password_456!")))
                .andExpect(status().isForbidden());

        verifyNoInteractions(userMapper);
        mvc.perform(get("/api/hello").session(session)).andExpect(status().isOk());
    }

    @Test
    void shouldRejectAnonymousPasswordChangeEvenWithCsrf() throws Exception {
        mvc.perform(post("/api/auth/change-password")
                        .servletPath("/api/auth/change-password")
                        .with(csrf().asHeader()).contentType(MediaType.APPLICATION_JSON)
                        .content(passwordChangeBody(PASSWORD, "Changed_Password_456!")))
                .andExpect(status().isUnauthorized());
        verifyNoInteractions(userMapper);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "null", "{", "{\"oldPassword\":null,\"newPassword\":null}"})
    void shouldRejectInvalidPasswordChangeBodyWithoutUpdating(String body) throws Exception {
        MockHttpSession session = loginAndGetSession();

        // 空字段、JSON null 及格式错误都不能执行更新或注销有效会话。
        mvc.perform(post("/api/auth/change-password")
                        .servletPath("/api/auth/change-password")
                        .session(session).with(csrf().asHeader())
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());

        verify(userMapper, never()).updatePassword(any(), any(), any());
        mvc.perform(get("/api/hello").session(session)).andExpect(status().isOk());
    }

    @Test
    void shouldRejectPasswordChangeAfterAccountDisabled() throws Exception {
        MockHttpSession session = loginAndGetSession();
        account.setStatus("DISABLED");

        mvc.perform(post("/api/auth/change-password")
                        .servletPath("/api/auth/change-password")
                        .session(session).with(csrf().asHeader())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordChangeBody(PASSWORD, "Changed_Password_456!")))
                .andExpect(status().isUnauthorized());

        verify(userMapper, never()).updatePassword(any(), any(), any());
        assertTrue(session.isInvalid());
    }

    private String passwordChangeBody(String oldPassword, String newPassword) {
        return objectMapper.writeValueAsString(
                Map.of("oldPassword", oldPassword, "newPassword", newPassword));
    }
}
