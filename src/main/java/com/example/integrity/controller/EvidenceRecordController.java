package com.example.integrity.controller;

import java.io.ByteArrayInputStream;
import java.io.File;
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

import com.example.integrity.service.DocumentService;
import com.example.integrity.service.EvidenceRecordService;

@RestController
@RequestMapping("/api/evidence/record")
public class EvidenceRecordController {

    @Autowired
    private DocumentService documentService;
    @Autowired
    private EvidenceRecordService evidenceRecordService;

    @PostMapping("/create")
    public ResponseEntity<InputStreamResource> createEvidenceRecord(@RequestParam("path") String path) {
        byte[] content = documentService.getFileContent(path);
        byte[] evidenceRecord;
        try {
            evidenceRecord = evidenceRecordService.createEvidenceRecord(content).toASN1Primitive().getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode evidence record", e);
        }

        InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(evidenceRecord));
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + path + ".ers\"")
                .body(resource);
    }

    @PostMapping("/renew/timestamp")
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

    @PostMapping("/renew/hashtree")
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

    @PostMapping("/verify")
    public ResponseEntity<Boolean> verifyEvidenceRecord(@RequestParam("filePath") String filePath,
            @RequestParam("erPath") String erPath) {
        byte[] content = documentService.getFileContent(filePath);
        File erFile = documentService.getFile(erPath);
        EvidenceRecord er = evidenceRecordService.parseEvidenceRecord(erFile);
        boolean result = evidenceRecordService.verifyEvidenceRecord(er, content);
        return ResponseEntity.ok(result);
    }

}
