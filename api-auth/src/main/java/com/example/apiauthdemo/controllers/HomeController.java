package com.example.apiauthdemo.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "Hello";
    }

    @GetMapping("/secured")
    public String secured(Authentication authentication) {
        return "Hello "+ authentication.getName();
    }

//    @GetMapping("/get-token")
//    public ResponseEntity<OAuth2AccessToken> getAccessToken(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
//        return ResponseEntity.ok(authorizedClient.getAccessToken());
//    }
//
//    @GetMapping("/get-email")
//    public String getEmail(@AuthenticationPrincipal OAuth2User oauth2User) {
//        return oauth2User.getAttribute("email");
//    }
}
