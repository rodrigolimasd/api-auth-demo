package com.example.apiclient.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class HomeController {

    @GetMapping("/secured")
    fun hello(): String = "Hello, secured"
}