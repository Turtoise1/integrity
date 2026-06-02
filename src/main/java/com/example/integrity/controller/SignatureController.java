package com.example.integrity.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.integrity.service.ConfigService;
import com.example.integrity.service.DigitalSignatureService;
import com.example.integrity.service.DocumentService;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

@RestController
@RequestMapping("/api/signature")
public class SignatureController {

    @Autowired
    private DigitalSignatureService digitalSignatureService;

    @Autowired
    private DocumentService documentService;

    @Autowired
    private ConfigService configService;

    @PostMapping("/create")
    public ResponseEntity<InputStreamResource> createSignature(@RequestParam("path") String path) {

        DSSDocument document = digitalSignatureService.sign(documentService.getDocuments(path),
                configService.getDefaultSignatureToken(), configService.getDefaultTrustedCertificateSource(),
                configService.getDefaultOnlineTSPSource());

        InputStreamResource resource = new InputStreamResource(document.openStream());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + path + "-signed-xades-lta.sce\"")
                .body(resource);
    }

    @PostMapping("/extend")
    public ResponseEntity<InputStreamResource> extendSignature(@RequestParam("path") String path) {
        List<DSSDocument> documents = documentService.getDocuments(path);
        if (documents.size() != 1) {
            return ResponseEntity.badRequest().build();
        }

        DSSDocument extendedDocument = digitalSignatureService.extendSignature(documents.get(0),
                configService.getDefaultSignatureToken(), configService.getDefaultTrustedCertificateSource(),
                configService.getDefaultOnlineTSPSource());

        InputStreamResource resource = new InputStreamResource(extendedDocument.openStream());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + extendedDocument.getName() + "\"")
                .body(resource);
    }

    @PostMapping("/verify")
    public ResponseEntity<Boolean> verifySignature(@RequestParam("path") String path) {
        List<DSSDocument> documents = documentService.getDocuments(path);
        if (documents.size() != 1) {
            return ResponseEntity.badRequest().build();
        }

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(configService.getDefaultTrustedCertificateSource());
        boolean allSignaturesValid = digitalSignatureService.validateSignature(documents.get(0), verifier);
        return ResponseEntity.ok(allSignaturesValid);
    }
}
