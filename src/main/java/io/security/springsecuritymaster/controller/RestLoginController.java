package io.security.springsecuritymaster.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestLoginController {

    @PostMapping("/api/login")
    public String restLogin(){
        return "restLogin";
    }
}
