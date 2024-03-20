package org.example.springsecurity2.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Security;

@RestController
@RequestMapping("/api/v1/greetings")
public class GreetingsController {
    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello form the API");
    }

    @GetMapping("/say-goodbye")
    public ResponseEntity<String> sayGoodbye() {
        return ResponseEntity.ok("Good Bye and See you later");
    }
}
