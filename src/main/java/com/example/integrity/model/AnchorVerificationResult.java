package com.example.integrity.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AnchorVerificationResult {
    private boolean match;
    private String storedHash;
    private String currentHash;
    private Long timestamp;
}
