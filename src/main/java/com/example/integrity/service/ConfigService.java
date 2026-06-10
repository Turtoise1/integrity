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
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import lombok.extern.slf4j.Slf4j;

@Slf4j
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
                    "src/test/resources/signer.p12",
                    new PasswordProtection("changeit".toCharArray()));
        } catch (Exception e) {
            throw new RuntimeException("Failed to load signing token", e);
        }
        return signatureToken;
    }

    public ExternalResourcesCRLSource getDefaultCrlSource() {
        // Use ExternalResourcesCRLSource for the local CRL file
        ExternalResourcesCRLSource crlSource = new ExternalResourcesCRLSource(
                new String("src/test/demoCA/crl/rootca.crl"));
        return crlSource;
    }

    public CommonTrustedCertificateSource getDefaultTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        // Add the TSA certificate
        addDfnCertificates(trustedCertificateSource);
        // Add signer certificates
        addSignerCertificates(trustedCertificateSource);
        return trustedCertificateSource;
    }

    private void addSignerCertificates(TrustedCertificateSource source) {
        String caDirectory = "src/test/resources/demoCA/";
        CertificateToken signerCert = DSSUtils.loadCertificate(new File(caDirectory + "certs/signer.crt"));
        source.addCertificate(signerCert);
        CertificateToken caCert = DSSUtils.loadCertificate(new File(caDirectory + "cacert.pem"));
        source.addCertificate(caCert);
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
        CertificateToken rootCert = DSSUtils
                .loadCertificate(new File(certDirectory + "GlobalRoot_Class_2.crt"));
        source.addCertificate(rootCert);
    }
}
