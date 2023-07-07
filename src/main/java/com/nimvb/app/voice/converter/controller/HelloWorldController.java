package com.nimvb.app.voice.converter.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/tests")
@SecurityRequirement(name = "bearer-authentication")
public class HelloWorldController {

    @GetMapping
    public String message(){
        return "Hello WOrld";
    }
}
