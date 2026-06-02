package com.example.integrity.service;

import java.io.File;
import java.security.KeyStore.PasswordProtection;

import org.springframework.stereotype.Service;

import com.example.integrity.model.HashAlgorithm;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;

@Service
public class ConfigService {

    public HashAlgorithm getDefaultHashAlgorithm() {
        return HashAlgorithm.SHA256;
    }

    public TSPSource getDefaultOnlineTSPSource() {
        final String tspServer = "https://zeitstempel.dfn.de/";
        return new OnlineTSPSource(tspServer);
    }

    public Pkcs12SignatureToken getDefaultSignatureToken() {
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

    public CommonTrustedCertificateSource getDefaultTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        // Add the TSA certificate
        addDfnCertificates(trustedCertificateSource);
        // Add default signature token
        getDefaultSignatureToken().getKeys().stream()
                .forEach(k -> trustedCertificateSource.addCertificate(k.getCertificate()));
        return trustedCertificateSource;
    }

    private void addDfnCertificates(TrustedCertificateSource source) {
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
