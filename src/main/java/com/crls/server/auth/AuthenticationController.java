package com.crls.server.auth;

import com.crls.server.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/*
the url of the endpoint is defined with @RequestMapping
this is a @RestController
this controller is used to manage the Tokens (and the 2 Auths)

this provides 2 endpoints:
- register: to create an account and then login
- authenticate: the login, used to generate token

we delegate the implementation of these endpoints to the service: AuthenticationService
*/


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service; //inject service
    private final UserRepository repository;//to create user


    //the object request of type RegisterRequest contains all the info to register: first name, last name, email and password
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        //if email/username exists, return error
        if (repository.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest().body(null);
        }
        if (request.getRole() == null) {
            return ResponseEntity.badRequest().body(null);
        }
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationDto request
    ) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request, response);
    }


}