package com.github.luoyubyte.backend.controller;

import com.github.luoyubyte.backend.dto.ChangePasswordRequest;
import com.github.luoyubyte.backend.mapper.UserMapper;
import com.github.luoyubyte.backend.service.PasswordService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import com.github.luoyubyte.backend.entity.SysUser;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserMapper userMapper;
    private final PasswordService passwordService;
    private final SessionRegistry sessionRegistry;
    //CsrfResponse负责把请求头名称和令牌作为JSON返回。接口完整地址是 /api/auth/csrf。
    @GetMapping("/csrf")
    public CsrfResponse csrf(CsrfToken csrfToken) {
        return new CsrfResponse(
                csrfToken.getHeaderName(),
                csrfToken.getToken()
        );
    }

    public record CsrfResponse(String headerName, String token) {
    }

    //注入账号查询组件用于获取当前账号的最新资料
    public AuthController(UserMapper userMapper,PasswordService passwordService,SessionRegistry sessionRegistry){
        this.userMapper =userMapper;
        this.passwordService = passwordService;
        this.sessionRegistry = sessionRegistry;
    }
    //增加接口方法和响应对象
    @GetMapping("/me")
    public CurrentUserResponse me(Authentication authentication) {
        //身份来自后端已验证的登录会话不接受前端传入工号冒充用户
        String employeeNo =authentication.getName();
        SysUser account =userMapper.findByEmployeeNo(employeeNo);

        if (account ==null ||!"ACTIVE".equals(account.getStatus())){
            throw  new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        //明确挑选可返回的字段，不直接返回包含密码哈希的SysUser
        return  new CurrentUserResponse(
                account.getId(),
                account.getEmployeeNo(),
                account.getName(),
                account.getRole(),
                account.getMustChangePassword()
        );
    }
    public record CurrentUserResponse(
            Long id,
            String employeeNo,
            String name,
            String role,
            Boolean mustChangePassword
    ) {
    }
    //增加改密接口
    @PostMapping("/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(
            Authentication authentication,
            @RequestBody ChangePasswordRequest body,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        // 修改对象来自已登录身份，不接受前端指定工号。
        // 校验或更新失败会抛异常，后面的会话注销不会执行。
        passwordService.changePassword(authentication.getName(), body);

        // 密码更新成功后，将当前账号所有已登记会话标记失效。
        // 其他浏览器下一次请求时，会被安全过滤器拒绝并注销。
        for (SessionInformation session :
                sessionRegistry.getAllSessions(
                        authentication.getPrincipal(), false)) {
            session.expireNow();
        }

        // 当前请求不用等下一次访问，立即注销登录并清理 Cookie。
        new SecurityContextLogoutHandler()
                .logout(request, response, authentication);

        new CookieClearingLogoutHandler("JSESSIONID")
                .logout(request, response, authentication);
    }

}
