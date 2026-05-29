package com.example.merkletree.utils;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;

public class TestUtils {
    public static void assertNear(Date expected, Date actual, long marginMs) {
        long diff = Math.abs(expected.getTime() - actual.getTime());
        if (diff > marginMs) {
            throw new AssertionError(
                    "Expected date: " + expected + " but was " + actual + " (difference: " + diff + " ms)");
        }
    }

    public static X509CertificateHolder loadCertificateFromPEM(String path) throws IOException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(path)))) {
            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder) {
                return (X509CertificateHolder) object;
            } else if (object instanceof Certificate) {
                return new X509CertificateHolder(((Certificate) object).getEncoded());
            } else {
                throw new IllegalArgumentException("Ungültiges PEM-Format: " + object.getClass());
            }
        }
    }

    public static X509CertificateHolder loadCertificateFromCer(String path) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line = reader.readLine();
            if (line == null || !line.startsWith("-----BEGIN CERTIFICATE-----")) {
                throw new IllegalArgumentException("Expected BEGIN CERTIFICATE.");
            }

            StringBuilder base64Builder = new StringBuilder();
            while (true) {
                line = reader.readLine();
                if (line == null || line.equals("-----END CERTIFICATE-----")) {
                    break;
                }
                base64Builder.append(line);
            }

            // 1. Base64-Daten dekodieren
            byte[] derBytes = Base64.getDecoder().decode(base64Builder.toString());

            // 2. X509CertificateHolder aus den DER-Bytes erstellen
            return new X509CertificateHolder(derBytes);
        }
    }
}
