package com.crls.server.config;

import com.crls.server.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//this hold all the app config, such as beans
//@Configuration at the start of the app, spring will pick up this class and try to implement and inject all the Beans that we declare here

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository repository;

    //fetch (get) the user from the database
    //.orElseThrow() in case user doesn't exist
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    //used in SecurityFilterChain, the http config
    //AuthenticationProvider: the data access object which is responsible for fetching the user details and encode password
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());//which userDetailsService to use in order to fetch info about our user
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    //the one responsible to manage the auth
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
