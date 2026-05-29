package com.example.merkletree.service;

import java.io.File;
import java.security.KeyStore.PasswordProtection;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;

@SpringBootTest
public class DigitalSignatureServiceTest {

    @Autowired
    private DigitalSignatureService digitalSignatureService;

    @Test
    public void testSign() {
        digitalSignatureService.sign(getDocumentsToSign(), getSignatureToken(), getTrustedCertificateSource(),
                getOnlineTSPSource());
    }

    private List<DSSDocument> getDocumentsToSign() {
        // Create a list of documents to sign
        List<DSSDocument> documentsToSign = new ArrayList<>();

        // Add all files from a folder (recursively)
        File folder = new File("src/test/resources/collection/");
        collectRecursive(folder, folder, documentsToSign);

        return documentsToSign;
    }

    private static void collectRecursive(File root, File current, List<DSSDocument> docs) {
        for (File file : current.listFiles()) {
            if (file.isDirectory()) {
                collectRecursive(root, file, docs);
            } else {
                // Preserve relative path inside ASiC container
                String relativePath = root.toPath().relativize(file.toPath()).toString();

                FileDocument doc = new FileDocument(file);
                doc.setName(relativePath);

                docs.add(doc);
            }
        }
    }

    private static TSPSource getOnlineTSPSource() {
        final String tspServer = "https://zeitstempel.dfn.de/";
        return new OnlineTSPSource(tspServer);
    }

    private Pkcs12SignatureToken getSignatureToken() {
        // Load the signing token (PKCS#12 file)
        Pkcs12SignatureToken signatureToken = null;
        try {
            signatureToken = new Pkcs12SignatureToken(
                    "src/test/resources/test.p12",
                    new PasswordProtection("changeit".toCharArray()));
        } catch (Exception e) {
            throw new RuntimeException("Failed to load signing token", e);
        }
        return signatureToken;
    }

    private CommonTrustedCertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();

        // Add the TSA certificate
        addTsaCertificates(trustedCertificateSource);
        return trustedCertificateSource;
    }

    private static void addTsaCertificates(TrustedCertificateSource source) {
        String certDirectory = "src/test/resources/certificates/";
        String dfnPkiDirectory = certDirectory + "dfn-pki-global-bundle/";
        CertificateToken timestampCert = DSSUtils
                .loadCertificate(new File(certDirectory + "PN_Zeitstempel_2023.cer"));
        source.addCertificate(timestampCert);
        CertificateToken issuingCert = DSSUtils
                .loadCertificate(new File(dfnPkiDirectory + "DFN-Verein_Global_Issuing_CA.cer"));
        source.addCertificate(issuingCert);
        CertificateToken intermediateCert = DSSUtils
                .loadCertificate(new File(dfnPkiDirectory + "DFN-Verein_Certification_Authority_2.cer"));
        source.addCertificate(intermediateCert);
        // root cert T-TeleSec GlobalRoot Class 2 should be preinstalled
    }
}
