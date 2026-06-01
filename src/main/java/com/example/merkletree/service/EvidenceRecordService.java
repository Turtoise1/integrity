package com.example.merkletree.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.CryptoInfos;
import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.merkletree.model.Composite;
import com.example.merkletree.model.FileComposite;
import com.example.merkletree.model.HashAlgorithm;
import com.example.merkletree.model.MerkleTreeNode;

@Service
public class EvidenceRecordService {

    @Autowired
    private ConfigService configService;

    @Autowired
    private ArchiveTimeStampingService archiveTimeStampingService;

    public EvidenceRecord createEvidenceRecord(File file) {

        HashAlgorithm hashAlgorithm = configService.getDefaultHashAlgorithm();
        FileComposite composite = new FileComposite(file);
        MerkleTreeNode root = buildMerkleTree(composite, hashAlgorithm);

        ArchiveTimeStamp archiveTimeStamp = archiveTimeStampingService.createArchiveTimeStamp(root.getHash(),
                hashAlgorithm);

        // cryptoInfos allows the storage of data useful in the validation of the archiveTimeStampSequence. This could
        // include possible Trust Anchors, certificates, revocation information, or the current definition of the
        // suitability of cryptographic algorithms, past and present (e.g., RSA 768-bit valid until 1998, RSA 1024-bit
        // valid until 2008, SHA1 valid until 2010). These items may be added based on the policy used. Since this data
        // is not protected within any timestamp, the data should be verifiable through other mechanisms.
        CryptoInfos cryptoInfos = new CryptoInfos(new Attribute[] {});
        EvidenceRecord evidenceRecord = new EvidenceRecord(cryptoInfos, null, archiveTimeStamp);

        return evidenceRecord;
    }

    public EvidenceRecord parseEvidenceRecord(File erFile) {
        try (FileInputStream fis = new FileInputStream(erFile)) {
            ASN1InputStream asn1In = new ASN1InputStream(fis);
            ASN1Primitive asn1Object = asn1In.readObject();
            return EvidenceRecord.getInstance(asn1Object);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse evidence record", e);
        }
    }

    public void timeStampRenewal(EvidenceRecord evidenceRecord) {
        ArchiveTimeStampSequence archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
        ArchiveTimeStampChain chain = archiveTimeStampSequence.getArchiveTimeStampChains()[0];
        chain = archiveTimeStampingService.timeStampRenewal(chain, configService.getDefaultHashAlgorithm());
    }

    public EvidenceRecord hashTreeRenewal(File file, EvidenceRecord oldER) {

        HashAlgorithm hashAlgorithm = configService.getDefaultHashAlgorithm();
        FileComposite composite = new FileComposite(file);
        MerkleTreeNode root = buildMerkleTree(composite, hashAlgorithm);

        AlgorithmIdentifier[] algorithms = new AlgorithmIdentifier[oldER.getDigestAlgorithms().length + 1];
        System.arraycopy(oldER.getDigestAlgorithms(), 0, algorithms, 0, oldER.getDigestAlgorithms().length);
        algorithms[algorithms.length - 1] = hashAlgorithm.getAlgorithmIdentifier();

        ArchiveTimeStampSequence sequence = oldER.getArchiveTimeStampSequence();
        try {
            sequence = archiveTimeStampingService.hashTreeRenewal(sequence, hashAlgorithm, root.getHash(), null);
        } catch (IOException e) {
            throw new RuntimeException("Failed to renew hash tree", e);
        }

        CryptoInfos cryptoInfos = new CryptoInfos(new Attribute[] {});
        EvidenceRecord newER = new EvidenceRecord(algorithms, cryptoInfos, null, sequence);
        return newER;
    }

    /**
     * Builds a merkle hash tree over the given {@code composite} using the specified {@code hashAlgorithm}.
     */
    public MerkleTreeNode buildMerkleTree(Composite composite, HashAlgorithm hashAlgorithm) {
        return new MerkleTreeNode(composite, hashAlgorithm);
    }
}
