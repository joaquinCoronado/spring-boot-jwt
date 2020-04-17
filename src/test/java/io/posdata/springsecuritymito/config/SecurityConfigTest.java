package io.posdata.springsecuritymito.config;

import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@RunWith(SpringRunner.class)
class SecurityConfigTest {

    @Autowired
    BCryptPasswordEncoder encoder;

    @Test
    void passwordEncoder() {
        String pass = "123";
        System.out.println("password " + encoder.encode(pass));
        System.out.println("match? " + encoder.matches(
                "123",
                "$2a$10$y3RhOMJP4RMH5VNU7OyAMeeIqhrMfHsH7bwFJFVVdtUzvQ74JoURq")
        );
    }
}