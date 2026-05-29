package com.example.merkletree.service;

import org.springframework.stereotype.Service;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureProfile;
import eu.europa.esig.dss.extension.SignedDocumentExtender;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import lombok.extern.slf4j.Slf4j;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;

import java.util.List;

@Slf4j
@Service
public class DigitalSignatureService {

    public void sign(List<DSSDocument> documentsToSign, Pkcs12SignatureToken signatureToken,
            CommonTrustedCertificateSource trustedCertificateSource, TSPSource tspSource) {

        // Get the first private key entry
        DSSPrivateKeyEntry privateKey = signatureToken.getKeys().get(0);
        // Add the signing certificate explicitly as trusted (for self-signed certs)
        trustedCertificateSource.addCertificate(privateKey.getCertificate());

        DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

        // Preparing parameters for the ASiC-E signature
        ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();

        // We choose the level of the signature (-B, -T, -LT or -LTA).
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        // We choose the container type (ASiC-S pr ASiC-E)
        parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        // We set the digest algorithm to use with the signature algorithm. You must use
        // the same parameter when you invoke the method sign on the token. The default
        // value is SHA256
        parameters.setDigestAlgorithm(digestAlgorithm);

        // We set the signing certificate
        parameters.setSigningCertificate(privateKey.getCertificate());
        // We set the certificate chain
        parameters.setCertificateChain(privateKey.getCertificateChain());

        // Create common certificate verifier
        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        // Create ASiC service for signature
        ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier);

        // Get the SignedInfo segment that need to be signed.
        ToBeSigned dataToSign = service.getDataToSign(documentsToSign, parameters);

        // This function obtains the signature value for signed information using the
        // private key and specified algorithm
        SignatureValue signatureValue = signatureToken.sign(dataToSign, digestAlgorithm, privateKey);

        // We invoke the xadesService to sign the document with the signature value
        // obtained in the previous step.
        DSSDocument signedDocument = service.signDocument(documentsToSign, parameters, signatureValue);

        // Initialize a SignedDocumentExtender, which will load the relevant
        // implementation of a DocumentExtender based on document's format
        SignedDocumentExtender documentExtender = SignedDocumentExtender.fromDocument(signedDocument);

        // configure commonCertificateVerifier if needed
        // Set the CertificateVerifier instantiated earlier
        documentExtender.setCertificateVerifier(certificateVerifier);

        // Set the TSPSource for a timestamp extraction
        documentExtender.setTspSource(tspSource);

        // Extend the document, by specifying the target augmentation profile
        signedDocument = documentExtender.extendDocument(SignatureProfile.BASELINE_T);

        // init revocation sources for CRL/OCSP requesting
        certificateVerifier.setCrlSource(new OnlineCRLSource());
        certificateVerifier.setOcspSource(new OnlineOCSPSource());

        // Trust anchors should be defined for revocation data requesting
        certificateVerifier.setTrustedCertSources(trustedCertificateSource);

        // Extend the document
        signedDocument = documentExtender.extendDocument(SignatureProfile.BASELINE_LT);

        // Extend the document
        signedDocument = documentExtender.extendDocument(SignatureProfile.BASELINE_LTA);

        // Verify the signed document
        validateSignature(signedDocument, certificateVerifier);

        try {
            // Save the signed container
            signedDocument.save("target/signed_container.asice");

            System.out.println("ASiC container with XAdES signatures created successfully!");
            System.out.println("Saved to: target/signed_container.asice");

        } catch (Exception e) {
            throw new RuntimeException("Failed to save signed container", e);
        } finally {
            signatureToken.close();
        }

    }

    public boolean validateSignature(DSSDocument signedDocument, CertificateVerifier certificateVerifier) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(certificateVerifier);
        Reports reports = validator.validateDocument();
        boolean allSignaturesValid = true;
        log.info("Validating {} signatures.", validator.getSignatures().size());
        for (AdvancedSignature signature : validator.getSignatures()) {
            if (!reports.getSimpleReport().isValid(signature.getId())) {
                allSignaturesValid = false;
            }
            log.info("Signature {} is {}", signature.getId(), allSignaturesValid ? "valid" : "invalid");
        }
        return allSignaturesValid;
    }

}
