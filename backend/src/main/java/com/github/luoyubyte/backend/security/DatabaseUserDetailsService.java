package com.github.luoyubyte.backend.security;

import com.github.luoyubyte.backend.entity.SysUser;
import com.github.luoyubyte.backend.mapper.UserMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//按工号查询数据库
@Service
public class DatabaseUserDetailsService implements UserDetailsService {
        private final UserMapper userMapper;

        public DatabaseUserDetailsService(UserMapper userMapper){
            this.userMapper=userMapper;
        }
    @Override
    public UserDetails loadUserByUsername(String employeeNo)
            throws UsernameNotFoundException {

        SysUser account = userMapper.findByEmployeeNo(employeeNo);

        if (account == null) {
            throw new UsernameNotFoundException("账号不存在");
        }

        return User.withUsername(account.getEmployeeNo())
                .password(account.getPasswordHash())
                .roles(account.getRole())
                .disabled(!"ACTIVE".equals(account.getStatus()))
                .build();
    }
}
