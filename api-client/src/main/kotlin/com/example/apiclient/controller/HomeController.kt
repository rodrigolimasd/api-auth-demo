package com.example.apiclient.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
class HomeController {

    @GetMapping("/secured")
    fun hello(principal: Principal): String = "Hello ${principal.name}"
}