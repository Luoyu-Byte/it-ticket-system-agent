package com.github.luoyubyte.backend.bootstrap;

import com.github.luoyubyte.backend.service.InitialAdminService;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.Console;

//本机初始化入口
@Component
@Profile("init-admin")
public class InitialAdminRunner implements ApplicationRunner {

    private final InitialAdminService initialAdminService;

    public InitialAdminRunner(InitialAdminService initialAdminService) {
        this.initialAdminService = initialAdminService;
    }

    @Override
    public void run(ApplicationArguments args) {
        // 【执行保护】必须有本机交互终端。
        // IDEA运行窗口或输出重定向可能没有Console，此时拒绝创建账号。
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException(
                    "初始化需要交互终端，请从本机终端启动，且不要重定向输出"
            );
        }

        String name = console.readLine("请输入初始管理员姓名：");
        String confirmation = console.readLine(
                "确认创建 INIT_ADMIN？请输入 CREATE："
        );

        // 没有明确确认就取消，不调用创建业务。
        if (!"CREATE".equals(confirmation)) {
            console.printf("已取消初始化，未创建账号。%n");
            return;
        }

        // 【核心：执行初始化】
        // Service负责检查、生成临时密码、编码及插入数据库。
        InitialAdminService.InitialAdminCredentials credentials =
                initialAdminService.initialize(name);

        // 【核心：本机凭据交付】
        // 有意向当前部署者显示一次，不使用应用日志输出凭据。
        // 不要截图、录屏、保存终端输出或转发给他人。
        console.printf("%n初始管理员创建成功。%n");
        console.printf("工号：%s%n", credentials.employeeNo());
        console.printf("临时密码：%s%n", credentials.temporaryPassword());
        console.printf("请安全保存，首次登录后立即改密。%n");
        console.flush();
    }
}
