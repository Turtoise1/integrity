package com.example.merkletree.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.example.merkletree.service.ConfigService;
import com.example.merkletree.service.DigitalSignatureService;
import com.example.merkletree.service.DocumentService;

import eu.europa.esig.dss.model.DSSDocument;

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
    public ResponseEntity<InputStreamResource> sign(@RequestParam("path") String path) {

        DSSDocument document = digitalSignatureService.sign(documentService.getDocuments(path),
                configService.getDefaultSignatureToken(), configService.getDefaultTrustedCertificateSource(),
                configService.getDefaultOnlineTSPSource());

        InputStreamResource resource = new InputStreamResource(document.openStream());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + document.getName() + "\"")
                .body(resource);
    }

}
