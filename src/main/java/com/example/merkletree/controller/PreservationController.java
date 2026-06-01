package com.example.merkletree.controller;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.List;

import org.bouncycastle.asn1.tsp.EvidenceRecord;
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
import com.example.merkletree.service.EvidenceRecordService;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

@RestController
@RequestMapping("/api/preservation")
public class PreservationController {

    @Autowired
    private DigitalSignatureService digitalSignatureService;

    @Autowired
    private DocumentService documentService;

    @Autowired
    private ConfigService configService;

    @Autowired
    private EvidenceRecordService evidenceRecordService;

    @PostMapping("/er")
    public ResponseEntity<InputStreamResource> createEvidenceRecord(@RequestParam("path") String path) {
        File file = documentService.getFile(path);
        byte[] evidenceRecord;
        try {
            evidenceRecord = evidenceRecordService.createEvidenceRecord(file).toASN1Primitive().getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode evidence record", e);
        }

        InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(evidenceRecord));
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + path + ".ers\"")
                .body(resource);
    }

    @PostMapping("/er/renew/timestamp")
    public ResponseEntity<InputStreamResource> renewEvidenceRecord(@RequestParam("erPath") String erPath) {
        File erFile = documentService.getFile(erPath);
        EvidenceRecord er = evidenceRecordService.parseEvidenceRecord(erFile);
        byte[] encodedER;
        try {
            evidenceRecordService.timeStampRenewal(er);
            encodedER = er.toASN1Primitive().getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to renew evidence record", e);
        }

        InputStreamResource resource = new InputStreamResource(
                new ByteArrayInputStream(encodedER));
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + erFile.getName() + "\"")
                .body(resource);
    }

    @PostMapping("/er/renew/hashtree")
    public ResponseEntity<InputStreamResource> renewHashTree(@RequestParam("filePath") String filePath,
            @RequestParam("erPath") String erPath) {
        File file = documentService.getFile(filePath);
        File erFile = documentService.getFile(erPath);
        EvidenceRecord er = evidenceRecordService.parseEvidenceRecord(erFile);
        byte[] encodedER;
        try {
            er = evidenceRecordService.hashTreeRenewal(file, er);
            encodedER = er.toASN1Primitive().getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to renew evidence record", e);
        }

        InputStreamResource resource = new InputStreamResource(
                new ByteArrayInputStream(encodedER));
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + erFile.getName() + "\"")
                .body(resource);
    }

    @PostMapping("/sign")
    public ResponseEntity<InputStreamResource> sign(@RequestParam("path") String path) {

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
    public ResponseEntity<InputStreamResource> extend(@RequestParam("path") String path) {
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
    public ResponseEntity<Boolean> verify(@RequestParam("path") String path) {
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
