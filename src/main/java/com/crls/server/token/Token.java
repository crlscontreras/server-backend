package com.crls.server.token;

import com.crls.server.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class Token {

    @Id
    @GeneratedValue
    public Integer id;

    @Column(unique = true)
    public String token;

    //we are just using BEARER tokens for now, so BEARER is the default
    @Enumerated(EnumType.STRING)
    public TokenType tokenType = TokenType.BEARER;

    //2 flags
    //when the user sends a log out request we update both of these
    //we can also implement a mechanism that revokes ALL the tokens when, for example, the backend restarts

    public boolean revoked;

    public boolean expired;

    //1 token belongs to 1 user
    //1 user can have many tokens

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    public User user;
}