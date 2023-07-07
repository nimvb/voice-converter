package com.nimvb.app.voice.converter.controller;

import com.nimvb.app.voice.converter.model.request.AuthenticationRequest;
import com.nimvb.app.voice.converter.model.response.JwtToken;
import com.nimvb.app.voice.converter.service.TokenService;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/token")
@RequiredArgsConstructor
public class AuthenticationController {

    private final TokenService tokenService;

    @PostMapping
    public JwtToken token(@RequestBody AuthenticationRequest request, Authentication authentication){
        return tokenService.encode(authentication);
    }
}
