package io.posdata.springsecuritymito.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("hello")
    @Secured("ROLE_USER")
    public String hello(){
        return "Hello World - Spring Security";
    }
}
