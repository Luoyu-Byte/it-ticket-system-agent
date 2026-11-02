package com.github.luoyubyte.backend.security;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

@Component
public class TemporaryPasswordGenerator {
    //// 使用适合安全用途的随机数生成器，不设置固定种子。
    private final SecureRandom secureRandom =new SecureRandom();

    public String generate(){
        //每次重新生成18字节随机数据，再转换为24个可复制的ASCII字符
        byte[] randomBytes = new byte[18];
        secureRandom.nextBytes(randomBytes);

        //Base64只是把随机字节表示成文本，不是加密，也不是密码哈希
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
    }
}
