package com.example.integrity;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
@Slf4j
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    public static final String PROVIDER_NAME = "BC";

    @PostConstruct
    public void setup() {
        setupCrypto();
    }

    public void setupCrypto() {

        Security.addProvider(new BouncyCastleProvider());

        if (Security.getProvider(PROVIDER_NAME) == null) {
            log.error("Bouncy Castle provider is not installed");
        } else {
            log.info("Bouncy Castle provider is installed.");
        }

        Security.setProperty("crypto.policy", "unlimited");
    }

}
