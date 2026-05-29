package com.example.merkletree.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.example.merkletree.model.Composite;
import com.example.merkletree.model.HashAlgorithm;
import com.example.merkletree.model.MerkleTreeNode;
import com.example.merkletree.utils.AllSelector;
import com.example.merkletree.utils.CryptoUtils;
import com.example.merkletree.utils.TestCompositeUtils;
import com.example.merkletree.utils.TestUtils;

public class TimeStampingServiceTest {

    @Autowired
    private TimeStampingService timeStampingService;

    @Test
    public void callRequestTimeStamp()
            throws IOException, CertificateException, OperatorCreationException, CMSException {
        // Random test values
        Composite testComposite = TestCompositeUtils.generateTestComposite();
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true); // also check certificates
        TimeStampRequest request = generator.generate(hashAlgorithm.getOid(), tree.getHash());

        TimeStampToken result = timeStampingService.requestTimeStamp(request);

        Date time = result.getTimeStampInfo().getGenTime();
        TestUtils.assertNear(new Date(), time, 2000);

        String issuerResult = result.getSID().getIssuer().toString();
        assertEquals(
                "C=DE,O=Verein zur Foerderung eines Deutschen Forschungsnetzes e. V.,OU=DFN-PKI,CN=DFN-Verein Global Issuing CA",
                issuerResult);

        String algorithmResult = result.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmResult);

        byte[] messageImprintDigest = result.getTimeStampInfo().getMessageImprintDigest();
        assertArrayEquals(tree.getHash(), messageImprintDigest);

        CMSSignedData signedData = result.toCMSSignedData();

        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();

        Store<X509CertificateHolder> certificates = signedData.getCertificates();
        assertEquals(1, signers.size());
        for (SignerInformation signer : signers) {

            // dfn includes signing certificate and parent CA certificates
            Collection<X509CertificateHolder> allCertificates = certificates.getMatches(new AllSelector<>());
            assertEquals(4, allCertificates.size());

            // get the certificate of the signer from the certificates of the response
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> signingCertificates = certificates.getMatches(result.getSID());
            assertEquals(1, signingCertificates.size());
            X509CertificateHolder certificateHolder = signingCertificates.iterator().next();
            X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(certificateHolder);
            SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(cert);

            boolean verificationResult = signer.verify(signerInformationVerifier);
            assertTrue(verificationResult, "Failed to verify signer information for certificate of "
                    + cert.getIssuerX500Principal().getName());

        }

    }

    @Test
    public void callRequestTimeStamp_withoutCertReq()
            throws IOException, CertificateException, OperatorCreationException, CMSException {
        // Random test values
        Composite testComposite = TestCompositeUtils.generateTestComposite();
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(false); // don't check certificates
        TimeStampRequest request = generator.generate(hashAlgorithm.getOid(), tree.getHash());

        TimeStampToken result = timeStampingService.requestTimeStamp(request);

        Date time = result.getTimeStampInfo().getGenTime();
        TestUtils.assertNear(new Date(), time, 2000);

        String issuerResult = result.getSID().getIssuer().toString();
        assertEquals(
                "C=DE,O=Verein zur Foerderung eines Deutschen Forschungsnetzes e. V.,OU=DFN-PKI,CN=DFN-Verein Global Issuing CA",
                issuerResult);

        String algorithmResult = result.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmResult);

        byte[] messageImprintDigest = result.getTimeStampInfo().getMessageImprintDigest();
        assertArrayEquals(tree.getHash(), messageImprintDigest);

        CMSSignedData signedData = result.toCMSSignedData();

        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();

        assertEquals(1, signers.size());
        for (SignerInformation signer : signers) {

            // ESSCertID hash from the signer attributes should have the hash of the certificate holder
            SigningCertificateV2 signingCertificate = SigningCertificateV2.getInstance(signer.getSignedAttributes()
                    .get(new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.47")).getAttrValues().getObjectAt(0)); // id-aa-signingCertificate
            ESSCertIDv2 essCertID = signingCertificate.getCerts()[0];

            X509CertificateHolder certificateHolder = TestUtils
                    .loadCertificateFromCer("src/test/resources/certificates/PN_Zeitstempel_2023.cer");

            HashAlgorithm essHashAlgorithm = HashAlgorithm.fromAlgorithmIdentifier(essCertID.getHashAlgorithm());
            byte[] expectedHash = CryptoUtils.hash(certificateHolder.getEncoded(), essHashAlgorithm);

            assertArrayEquals(expectedHash, essCertID.getCertHash(), "Exptected certificate hash "
                    + Hex.toHexString(expectedHash) + " but got " + Hex.toHexString(essCertID.getCertHash())
                    + " from EssCertID!");
        }

    }

}
