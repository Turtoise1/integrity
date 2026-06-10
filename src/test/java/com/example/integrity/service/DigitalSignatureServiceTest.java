package com.example.integrity.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

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

        digitalSignatureService.sign(documentService.getDocuments("pdf"),
                configService.getDefaultSignatureToken(), configService.getDefaultTrustedCertificateSource(),
                configService.getDefaultOnlineTSPSource());
    }
}
