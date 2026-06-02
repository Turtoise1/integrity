package com.example.merkletree.controller;

import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.merkletree.service.DistributedSystemService;

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/distributed/system")
public class DistributedSystemController {

    private final DistributedSystemService distributedSystemService;

    public DistributedSystemController(DistributedSystemService distributedSystemService) {
        this.distributedSystemService = distributedSystemService;
    }

    @PostMapping("/distribute")
    public ResponseEntity<Void> distribute(@RequestParam("path") String path) {
        try {
            distributedSystemService.distribute(path);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to distribute file: " + path, e);
        }
    }

    @GetMapping("/list/data")
    public ResponseEntity<List<String>> listData() {
        try {
            List<String> files = distributedSystemService.listData();
            return ResponseEntity.ok(files);
        } catch (Exception e) {
            throw new RuntimeException("Failed to list data", e);
        }
    }

    @GetMapping("/retrieve")
    public ResponseEntity<InputStreamResource> retrieve(@RequestParam("path") String path) {
        try {
            byte[] content = distributedSystemService.retrieve(path);
            if (content == null) {
                return ResponseEntity.notFound().build();
            }

            InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(content));
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + path + "\"")
                    .body(resource);
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve file: " + path, e);
        }
    }
}
