package com.spring.keycloak;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/")
public class HelloIndiaController {

    @GetMapping("/hello")
    public String helloWorld() {
        return "Hello India!";
    }

    @GetMapping("/hello/{user}")
    @PreAuthorize("hasAuthority('SCOPE_profile')") // allows only specific roles to access
    public ResponseEntity<String> helloUser(@PathVariable String user) {
        return new ResponseEntity<>("Hello " + user.toUpperCase(), HttpStatus.CREATED);
    }
}
