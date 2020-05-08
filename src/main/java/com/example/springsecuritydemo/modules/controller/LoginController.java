package com.example.springsecuritydemo.modules.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }


    //security不需要手写登陆方法，此方法不会进入
    @PostMapping("/user/login")
    public String login(String username, String password) {
        System.out.println("login, username:" + username + ", password:" + password);
        return "login ok";
    }
}
