package com.example.integrity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.integrity.model.AnchorVerificationResult;
import com.example.integrity.service.BlockchainService;

import java.util.List;

@RestController
@RequestMapping("/api/blockchain")
public class BlockchainController {

    @Autowired
    private BlockchainService blockchainService;

    @PostMapping("/anchor")
    public ResponseEntity<String> anchor(@RequestParam("path") String path) {
        try {
            String result = blockchainService.storeHash(path);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            throw new RuntimeException("Failed to anchor file: " + path, e);
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<AnchorVerificationResult> verify(@RequestParam("path") String path) {
        try {
            AnchorVerificationResult result = blockchainService.verifyHash(path);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            throw new RuntimeException("Failed to verify file: " + path, e);
        }
    }

    @GetMapping("/list/data")
    public ResponseEntity<List<String>> listData() {
        try {
            List<String> files = blockchainService.listAnchoredFiles();
            return ResponseEntity.ok(files);
        } catch (Exception e) {
            throw new RuntimeException("Failed to list anchored files", e);
        }
    }
}
