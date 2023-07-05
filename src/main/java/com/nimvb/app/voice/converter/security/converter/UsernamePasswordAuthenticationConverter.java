package com.nimvb.app.voice.converter.security.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimvb.app.voice.converter.model.request.AuthenticationRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.io.IOException;

@RequiredArgsConstructor
public class UsernamePasswordAuthenticationConverter implements AuthenticationConverter {

    private final ObjectMapper mapper;

    @Override
    public Authentication convert(HttpServletRequest request) {
        try {
            AuthenticationRequest authenticationRequest = mapper.readValue(request.getInputStream(), AuthenticationRequest.class);
            return UsernamePasswordAuthenticationToken.unauthenticated(authenticationRequest.username(),authenticationRequest.password());
        } catch (IOException ignored) {

        }
        return null;
    }
}
