package com.crls.server.config;

//import com.crls.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.beans.Transient;
import java.io.IOException;
import java.security.Security;

import jakarta.transaction.TransactionScoped;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/*
we need to tell spring that we want this class to be managed bean, to do so que need to annotate it with @Component or @Service/@Repository (they extend component)

@RequiredArgsConstructor: it will create a constructor using any final field that we declare

1:  when we send a http request to our server the first thing we do is call the JwtAuthenticationFilter
    to check if we have a JWT Token,
    so inside the method "doFilterInternal" we perform the operation to check that

2:  after checking if we have a JWT Token, we need to call the UserDetailsService to check if we have the user in our database or not
    but first we need to call a JwtService to extract the username from the request
*/
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    /*
    when we send a http request to our server it's going to go through a set of security filter chains

    filterChain: a collection of security filters, chain of responsibility design pattern
    doFilter(request, response): Causes the next filter in the chain to be invoked. you are handing the http request/response to the next filter in your filter chain.
     */
    @Override
    protected void doFilterInternal(      @NonNull HttpServletRequest request,
                                          @NonNull HttpServletResponse response,
                                          @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getServletPath().contains("/api/v1/auth")) {
            filterChain.doFilter(request, response);
            return;
        }
        //when we make a call to the API we pass the token in the header called "Authorization"
        final String authHeader = request.getHeader("Authorization");//the header is part of the request
        final String jwt;
        final String userEmail;
        //the header should exist and the Bearer token always start with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        //extract the token from header
        jwt = authHeader.substring(7);//7 because of: "Bearer "
        //2:

        userEmail = jwtService.extractUsername(jwt);


    }
}
