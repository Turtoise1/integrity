package com.example.merkletree.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.example.integrity.service.ConfigService;
import com.example.integrity.service.DigitalSignatureService;
import com.example.integrity.service.DocumentService;

@SpringBootTest
public class DigitalSignatureServiceTest {

    @Autowired
    private DigitalSignatureService digitalSignatureService;

    @Autowired
    private ConfigService configService;

    @Autowired
    private DocumentService documentService;

    @Test
    public void testSign() {
        digitalSignatureService.sign(documentService.getDocuments("collection"),
                configService.getDefaultSignatureToken(), configService.getDefaultTrustedCertificateSource(),
                configService.getDefaultOnlineTSPSource());
    }
}
