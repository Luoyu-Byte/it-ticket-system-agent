package com.github.luoyubyte.backend.security;

import com.github.luoyubyte.backend.entity.SysUser;
import com.github.luoyubyte.backend.mapper.UserMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Map;

// 不加 @Component：稍后直接加入安全过滤器链，避免被重复注册。
public class AccountStateFilter extends OncePerRequestFilter {

    private final UserMapper userMapper;
    private final ObjectMapper objectMapper;
    private final SecurityContextLogoutHandler logoutHandler =
            new SecurityContextLogoutHandler();

    public AccountStateFilter(
            UserMapper userMapper,
            ObjectMapper objectMapper
    ) {
        this.userMapper = userMapper;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        // 未登录请求交给原有安全规则处理，不在这里查询数据库。
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        // Session 中的身份可能仍然有效，但数据库中的账号状态已经改变。
        // 每次访问都读取最新状态，避免停用账号继续使用旧会话。
        SysUser account =
                userMapper.findByEmployeeNo(authentication.getName());

        if (account == null || !"ACTIVE".equals(account.getStatus())) {
            logoutHandler.logout(request, response, authentication);
            writeError(
                    response,
                    401,
                    "SESSION_INVALID",
                    "登录状态已失效，请重新登录"
            );
            return;
        }

        // 必须改密时保留登录身份，但禁止进入普通业务接口。
        if (Boolean.TRUE.equals(account.getMustChangePassword())
                && !isAllowedBeforePasswordChange(request)) {
            writeError(
                    response,
                    403,
                    "PASSWORD_CHANGE_REQUIRED",
                    "请先修改初始密码"
            );
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isAllowedBeforePasswordChange(
            HttpServletRequest request
    ) {
        String method = request.getMethod();
        String path = request.getServletPath();

        // 按请求方法和完整路径放行，不直接放行整个 /api/auth/**。
        // 改密和退出接口后续实现；这里仅提前声明访问规则。
        return ("GET".equals(method)
                && ("/api/auth/me".equals(path)
                || "/api/auth/csrf".equals(path)))
                || ("POST".equals(method)
                && ("/api/auth/change-password".equals(path)
                || "/api/auth/logout".equals(path)));
    }

    private void writeError(
            HttpServletResponse response,
            int status,
            String code,
            String message
    ) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(
                objectMapper.writeValueAsString(
                        Map.of("code", code, "message", message)
                )
        );
    }
}