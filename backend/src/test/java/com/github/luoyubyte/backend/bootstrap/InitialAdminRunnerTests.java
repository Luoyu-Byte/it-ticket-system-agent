package com.github.luoyubyte.backend.bootstrap;

import com.github.luoyubyte.backend.service.InitialAdminService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.*;

// 仅模拟初始化业务，不访问数据库，也不输出真实凭据。
class InitialAdminRunnerTests {

    private final InitialAdminService service = mock(InitialAdminService.class);

    @Test
    void shouldNotLoadRunnerWithDefaultProfile() {
        try (var context = createContext(null)) {
            assertTrue(context.getBeansOfType(InitialAdminRunner.class).isEmpty());
            verifyNoInteractions(service);
        }
    }

    @Test
    void shouldNotLoadRunnerWithOtherProfile() {
        try (var context = createContext("test")) {
            assertTrue(context.getBeansOfType(InitialAdminRunner.class).isEmpty());
            verifyNoInteractions(service);
        }
    }

    @Test
    void shouldLoadRunnerOnlyWithInitAdminProfile() {
        try (var context = createContext("init-admin")) {
            assertNotNull(context.getBean(InitialAdminRunner.class));

            // 普通Spring上下文只验证Profile与注入，不冒充Boot已执行run。
            verifyNoInteractions(service);
        }
    }

    @Test
    void shouldRejectExecutionWithoutInteractiveConsole() {
        // Surefire通常不提供交互Console；若运行环境提供Console则跳过，避免等待输入。
        assumeTrue(System.console() == null, "本项只验证非交互环境");
        InitialAdminRunner runner = new InitialAdminRunner(service);

        assertThrows(IllegalStateException.class,
                () -> runner.run(new DefaultApplicationArguments(new String[0])));
        verifyNoInteractions(service);
    }

    private AnnotationConfigApplicationContext createContext(String profile) {
        var context = new AnnotationConfigApplicationContext();
        if (profile != null) {
            context.getEnvironment().setActiveProfiles(profile);
        }
        context.registerBean(InitialAdminService.class, () -> service);
        context.scan("com.github.luoyubyte.backend.bootstrap");
        context.refresh();
        return context;
    }
}
