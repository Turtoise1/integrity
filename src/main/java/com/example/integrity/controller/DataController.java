package com.example.integrity.controller;

import org.springframework.web.bind.annotation.RestController;

import com.example.integrity.service.DocumentService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@RestController
@RequestMapping("/api/data")
public class DataController {

    @Autowired
    private DocumentService documentService;

    @GetMapping("list/paths")
    public ResponseEntity<List<String>> listPaths() {
        return ResponseEntity.ok(documentService.listPaths());
    }

    @PostMapping(value = "upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Void> upload(HttpServletRequest request) throws IOException, ServletException {
        try {
            documentService.acceptDocuments(request.getParts());
            return ResponseEntity.ok().build();
        } catch (IOException e) {
            log.error("Failed to upload documents", e);
            return ResponseEntity.status(500).build();
        }
    }

}
