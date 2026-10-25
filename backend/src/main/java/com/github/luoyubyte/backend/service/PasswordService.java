package com.github.luoyubyte.backend.service;

import com.github.luoyubyte.backend.dto.ChangePasswordRequest;
import com.github.luoyubyte.backend.entity.SysUser;
import com.github.luoyubyte.backend.mapper.UserMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;


//业务层，判断能不能改密码，Mapper负责执行更新
@Service
public class PasswordService {
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    //通过构造方法注入数据库访问和密码编码器
    public PasswordService(UserMapper userMapper,PasswordEncoder passwordEncoder){
        this.passwordEncoder=passwordEncoder;
        this.userMapper=userMapper;
    }

    public void changePassword(String employeeNo, ChangePasswordRequest request){
        //工号由后续Controller 从登录身份中取得
        //不能使用前端请求参数指定要修改的账号
        if (request == null||request.oldPassword()==null||request.oldPassword().isBlank()|| request.newPassword() == null
                || request.newPassword().isBlank()){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"原密码和新密码不能为空");
        }
        String oldPassword= request.oldPassword();
        String newPassword= request.newPassword();
        //不对密码调用trim，也不能截断密码
        //当前BCrypt 输入按UTF-8字节计算上限
        if (oldPassword.getBytes(StandardCharsets.UTF_8).length>72){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"原密码超出允许长度");
        }
        if (newPassword.codePointCount(0,newPassword.length())<15 || newPassword.getBytes(StandardCharsets.UTF_8).length > 72){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"新密码至少15个字符，且UTF-8编码不能超过72字节");
        }
        //查询最新账号资料，不使用前端提供的账号状态或密码哈希
        SysUser account=userMapper.findByEmployeeNo(employeeNo);

        if (account==null||!"ACTIVE".equals(account.getStatus())){
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        //matches 用于校验，不能重新encode后比较两个哈希字符串
        if (!passwordEncoder.matches(oldPassword,account.getPasswordHash())){
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "原密码不正确"
            );
        }
        if (newPassword.equals(oldPassword)) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "新密码不能与原密码相同"
            );
        }

        //数据库只接受新密码哈希
        //同时提交此前读取的哈希，防止覆盖其他并发改密结果
        String newPasswordHash = passwordEncoder.encode(newPassword);

        int affectedRows = userMapper.updatePassword(
                account.getId(),
                account.getPasswordHash(),
                newPasswordHash
        );
        if (affectedRows!=1){
            throw new ResponseStatusException(HttpStatus.CONFLICT,"账号状态或密码已发生变化，请重新登录后重试");
        }

    }
}
