package com.nimvb.app.voice.converter.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimvb.app.voice.converter.security.converter.UsernamePasswordAuthenticationConverter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


public class UsernamePasswordAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager         authenticationManager;
    private final UsernamePasswordAuthenticationConverter authenticationConverter;
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    public UsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager, ObjectMapper mapper) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
        this.authenticationConverter = new UsernamePasswordAuthenticationConverter(mapper);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        Authentication authRequest = authenticationConverter.convert(request);
        if (authRequest == null) {
            this.logger.trace("Did not process authRequest request since failed to find "
                    + "username and password in Basic Authorization header");
            chain.doFilter(request, response);
            return;
        }
        try {
            Authentication  authResult = this.authenticationManager.authenticate(authRequest);
            SecurityContext context    = this.securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authResult);
            this.securityContextHolderStrategy.setContext(context);
        }catch (Exception ex){
            this.securityContextHolderStrategy.clearContext();
        }
        chain.doFilter(request,response);
    }
}
