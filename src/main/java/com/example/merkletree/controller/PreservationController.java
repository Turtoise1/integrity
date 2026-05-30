package com.example.merkletree.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.example.merkletree.service.ConfigService;
import com.example.merkletree.service.DigitalSignatureService;
import com.example.merkletree.service.DocumentService;

@RestController
@RequestMapping("/api/preservation")
public class PreservationController {

    @Autowired
    private DigitalSignatureService digitalSignatureService;

    @Autowired
    private DocumentService documentService;

    @Autowired
    private ConfigService configService;

    @PostMapping("/sign")
    public ResponseEntity<Void> sign(@RequestParam("path") String path) {

        digitalSignatureService.sign(documentService.getDocuments(path),
                configService.getDefaultSignatureToken(), configService.getDefaultTrustedCertificateSource(),
                configService.getDefaultOnlineTSPSource());

        return ResponseEntity.ok().build();
    }

}
