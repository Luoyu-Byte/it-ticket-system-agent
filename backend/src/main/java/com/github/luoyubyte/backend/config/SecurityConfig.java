package com.github.luoyubyte.backend.config;

import jakarta.servlet.http.HttpSessionEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import tools.jackson.databind.ObjectMapper;
import java.util.Map;
import com.github.luoyubyte.backend.mapper.UserMapper;
import com.github.luoyubyte.backend.security.AccountStateFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
public class SecurityConfig {
    @Bean
    public PasswordEncoder passwordEncoder(){
        //创建框架提供密码的编码器
        return
                PasswordEncoderFactories.createDelegatingPasswordEncoder();
        /*
        * 之后创建账号时调用：passwordEncoder.encode(原始密码);
        * 登录校验时调用：passwordEncoder.matches(输入的密码, 数据库中的哈希);
        * */
    }
    @Bean    //添加哪些请求需要登录
    public  SecurityFilterChain
    securityFilterChain(HttpSecurity http,DaoAuthenticationProvider authenticationProvider,ObjectMapper objectMapper,UserMapper userMapper,SessionRegistry sessionRegistry) //HttpSecurity 用来描述安全规则的配置工具
        throws Exception {

        http.authenticationProvider(authenticationProvider);

        http.authorizeHttpRequests(authorize ->
                authorize
                        .requestMatchers(HttpMethod.POST,"/api/auth/login").permitAll()
                        .requestMatchers(HttpMethod.GET,"/api/auth/csrf").permitAll()
                        .anyRequest().authenticated()
                );
            //requestMatchers匹配指定的请求方案和地址
            //anyRequest().authenticated()：其他请求都必须先登录。规则按顺序匹配，兜底规则放最后。
        http.exceptionHandling(exceptions ->
                exceptions
                        .authenticationEntryPoint(
                                new
                                        HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
                        )

        );
        //只关闭“记住被拦截请求”的功能，不关闭登录 Session。
        http.requestCache(cache -> cache.disable());


        //告诉Spring Securit在哪里可以接受登录请求，读取哪些字段，以及登录成功和登录失败返回什么
        http.formLogin(form -> form
                    .loginPage("/api/auth/login")
                    .loginProcessingUrl("/api/auth/login")
                    .usernameParameter("employeeNo")
                    .passwordParameter("password")
                    .successHandler((request, response, authentication) -> {
                        response.setStatus(200);
                        response.setContentType("application/json;charset=UTF-8");

                        response.getWriter().write(
                                objectMapper.writeValueAsString(
                                        Map.of("employeeNo", authentication.getName())
                                )
                        );
                    })
                    .failureHandler((request, response, exception) -> {
                        response.setStatus(401);
                        response.setContentType("application/json;charset=UTF-8");

                        response.getWriter().write(
                                objectMapper.writeValueAsString(
                                        Map.of(
                                                "code", "INVALID_CREDENTIALS",
                                                "message", "工号或密码错误"
                                        )
                                )
                        );
                    })
            );

            // 退出由 Spring Security 处理。
            // 保留 CSRF 保护，因此前端需要携带当前会话的 Cookie 和有效令牌，
            // 使用 POST /api/auth/logout 发起退出。
            http.logout(logout -> logout
                    .logoutUrl("/api/auth/logout")

                    // 注销当前 Session，并清除当前登录身份。
                    // 这里只退出当前会话，不影响其他设备上的登录。
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)

                    // 通知浏览器删除保存会话标识的 Cookie。
                    .deleteCookies("JSESSIONID")

                    // 接口退出成功只返回 204，无响应正文，也不跳转页面。
                    .logoutSuccessHandler((request, response, authentication) ->
                            response.setStatus(HttpStatus.NO_CONTENT.value())
                    )
            );
            // 此时已能读取登录身份，在进入接口权限判断前检查账号状态
            http.addFilterBefore(
                    new AccountStateFilter(userMapper, objectMapper),
                    AuthorizationFilter.class
            );
            // 开启登录会话登记，但不限制同一账号的登录数量。
            // -1 不是无限登录时长，原来的空闲8小时配置仍然生效。
            http.sessionManagement(session -> session
                    .maximumSessions(-1)
                    .sessionRegistry(sessionRegistry)
                    // 后续改密时可将旧会话标记失效。
// 旧会话再次发请求时，框架会注销它，并返回401，不跳转页面。
                            .expiredSessionStrategy(event -> {
                                var response = event.getResponse();
                                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                                response.setContentType("application/json;charset=UTF-8");
                                response.getWriter().write(
                                        objectMapper.writeValueAsString(
                                                Map.of(
                                                        "code", "SESSION_INVALID",
                                                        "message", "登录状态已失效，请重新登录"
                                                )
                                        )
                                );
                            })
            );
            return http.build();
    }
    @Bean //组织查询工号和校验输入密码，完成账号认证
    public DaoAuthenticationProvider
    authenticationProvider(
        UserDetailsService userDetailsService,PasswordEncoder passwordEncoder
    ){
        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    //会话登记
    //保存已登录会话语用户的关联
    //当前但实例版本保存在内存里，应用重启后登录
    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }
    //将容器的会话销毁事件通知给Spring
    //让登录表及时清理已退出或超时的会话
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher(){
        return new HttpSessionEventPublisher();
    }
}
