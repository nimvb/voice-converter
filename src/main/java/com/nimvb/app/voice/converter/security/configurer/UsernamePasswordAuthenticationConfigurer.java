package com.nimvb.app.voice.converter.security.configurer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimvb.app.voice.converter.filter.UsernamePasswordAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@RequiredArgsConstructor
public class UsernamePasswordAuthenticationConfigurer <B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<UsernamePasswordAuthenticationConfigurer<B>, B> {

    private final ObjectMapper mapper;


    @Override
    public void configure(B builder) throws Exception {
        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        builder.addFilterAfter(new UsernamePasswordAuthenticationFilter(authenticationManager,mapper), LogoutFilter.class);
    }
}
