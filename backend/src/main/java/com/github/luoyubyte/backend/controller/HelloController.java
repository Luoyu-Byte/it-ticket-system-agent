package com.github.luoyubyte.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping(value="/api/hello",produces = "text/plain;charset=UTF-8")
    public String hello(){
        return "工单系统启动完成";
    }
}
