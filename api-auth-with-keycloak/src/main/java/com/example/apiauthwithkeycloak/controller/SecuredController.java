package com.example.apiauthwithkeycloak.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredController {

    @GetMapping("/get-token")
    public ResponseEntity<OAuth2AccessToken> getAccessToken(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        return ResponseEntity.ok(authorizedClient.getAccessToken());
    }

    @GetMapping
    public String hello() {
        return "hello";
    }

    @GetMapping("/admin")
    public String admin() {
        return "hello";
    }

    @GetMapping("/user")
    public String user() {
        return "hello";
    }


}
