package com.example.merkletree.model;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;

public enum HashAlgorithm {
    SHA256("SHA-256", TSPAlgorithms.SHA256),
    SHA512("SHA-512", TSPAlgorithms.SHA512);

    private String algorithmName;
    private ASN1ObjectIdentifier oid;

    HashAlgorithm(String algorithmName, ASN1ObjectIdentifier tspOid) {
        this.algorithmName = algorithmName;
        this.oid = tspOid;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }

    public MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return algorithmName;
    }

    public static HashAlgorithm fromAlgorithmIdentifier(AlgorithmIdentifier hashAlgorithm) {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            if (algorithm.getOid().equals(hashAlgorithm.getAlgorithm())) {
                return algorithm;
            }
        }
        return null;
    }
}
