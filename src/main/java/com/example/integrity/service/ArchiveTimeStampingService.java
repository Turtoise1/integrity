package com.example.integrity.service;

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampSequence;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.integrity.model.HashAlgorithm;
import com.example.integrity.utils.CryptoUtils;

/**
 * Service responsible for generating and managing archive time stamps according to RFC 4998
 * (https://datatracker.ietf.org/doc/html/rfc4998).
 */
@Service
public class ArchiveTimeStampingService {

    @Autowired
    private TimeStampingService timeStampingService;

    /**
     * According to the RFC 4998 hash tree renewal described in
     * https://datatracker.ietf.org/doc/html/rfc4998#section-5.2, all previous chains of the given sequence must be
     * covered by a new archive timestamp.
     *
     * This method needs to be called before the hash algorithm used for the generation of the hash tree is no longer
     * secure. Before calling this method, the old hash tree must be regenerated using a new secure hash algorithm.
     *
     * @param sequence        The archive time stamp sequence to be renewed.
     * @param hashAlgorithm   The new secure hash algorithm.
     * @param rootHash        The root hash of the hash tree generated with the new hash algorithm.
     * @param reducedHashTree The part of the new hash tree to verify a specific document the archive time stamp
     *                        sequence has been used for previously aswell.
     *
     * @return The updated archive time stamp sequence.
     * @throws IOException if an error occurs while DER-encoding the sequence.
     */
    public ArchiveTimeStampSequence hashTreeRenewal(ArchiveTimeStampSequence sequence,
            HashAlgorithm hashAlgorithm, byte[] rootHash, PartialHashtree[] reducedHashTree) throws IOException {
        // Step 1 and 2 are to obtain the new secure hash algorithm and regenerate the hash tree using the new
        // algorithm.

        // Step 3: Generate the hash value ha = H(atsc) where atsc is the DER-encoded archive time stamp sequence
        byte[] atsc = sequence.getEncoded();
        byte[] ha = CryptoUtils.hash(atsc, hashAlgorithm);

        // Step 4: Concatenate h with ha where h is the new merkle tree root hash
        byte[] h = rootHash;
        byte[] concatenated = new byte[h.length + ha.length];
        System.arraycopy(h, 0, concatenated, 0, h.length);
        System.arraycopy(ha, 0, concatenated, h.length, ha.length);

        // Step 5: Build a new archive time stamp for the concatenated hash value
        ArchiveTimeStamp newTimestamp = createArchiveTimeStamp(rootHash, reducedHashTree, hashAlgorithm);

        // Step 6: Create new ArchiveTimeStampChain containing the new Archive Timestamp and append this
        // ArchiveTimeStampChain to the ArchiveTimeStampSequence.
        ArchiveTimeStampChain newChain = new ArchiveTimeStampChain(newTimestamp);
        return sequence.append(newChain);
    }

    /**
     * According to the RFC 4998 timestamp renewal described in
     * https://datatracker.ietf.org/doc/html/rfc4998#section-5.2, a new archive timestamp is generated. It covers the
     * old chains timestamps. Must be called when the last timestamp becomes invalid. This is the case when the private
     * key of the timestamping unit is compromised or before the hash algorithm used for the generation of the last
     * timestamp is no longer secure for the key size.
     *
     * @param chain         The existing chain of archive timestamps.
     * @param hashAlgorithm The hash algorithm to be used for the timestamp renewal. If {@code null}, the same algorithm
     *                      that was used for the last timestamp will be used.
     * @return The updated chain of archive timestamps.
     */
    public ArchiveTimeStampChain timeStampRenewal(ArchiveTimeStampChain chain, HashAlgorithm hashAlgorithm) {
        ArchiveTimeStamp latest = chain.getArchiveTimestamps()[chain.getArchiveTimestamps().length - 1];
        if (hashAlgorithm == null) {
            hashAlgorithm = HashAlgorithm.fromAlgorithmIdentifier(latest.getDigestAlgorithm());
        }
        // The content of the timeStamp field of the old Archive Timestamp has to be hashed and timestamped by a new
        // Archive Timestamp. The new Archive Timestamp MAY not contain a reducedHashtree field, if the timestamp only
        // simply covers the previous timestamp. However, generally one can collect a number of old Archive Timestamps
        // and build the new hash tree with the hash values of the content of their timeStamp fields.
        byte[] timestampContent;
        try {
            timestampContent = latest.getTimeStamp().getContent().toASN1Primitive().getEncoded();
        } catch (IOException e) {
            throw new RuntimeException("The content of the timeStamp field could not be encoded.", e);
        }
        byte[] hash = CryptoUtils.hash(timestampContent, hashAlgorithm);
        ArchiveTimeStamp timestamp = createArchiveTimeStamp(hash, hashAlgorithm);
        return chain.append(timestamp);
    }

    /**
     * Create an archive timestamp according to RFC 4998.
     *
     * @param hash The hash value that should be timestamped.
     * @return The created archive timestamp.
     */
    public ArchiveTimeStamp createArchiveTimeStamp(byte[] hash, HashAlgorithm hashAlgorithm) {

        // Obtain a timestamp for the root hash value
        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        TimeStampRequest request = generator.generate(hashAlgorithm.getOid(), hash);
        ContentInfo timeStamp = timeStampingService.requestTimeStamp(request).toCMSSignedData().toASN1Structure();

        // Create the archive timestamp
        // The new Archive Timestamp MUST be added to the ArchiveTimestampChain. This hash tree of the new Archive
        // Timestamp MUST use the same hash algorithm as the old one, which is specified in the digestAlgorithm
        ArchiveTimeStamp archiveTimeStamp = new ArchiveTimeStamp(timeStamp);
        return archiveTimeStamp;
    }

    /**
     * Create an archive timestamp according to RFC 4998.
     *
     * @param rootHash        The root hash of the Merkle tree.
     * @param reducedHashTree The reduced hash tree containing the path to some node that shall be archived.
     * @param hashAlgorithm   The hash algorithm used to create the hash tree.
     * @return The created archive timestamp.
     */
    public ArchiveTimeStamp createArchiveTimeStamp(byte[] rootHash, PartialHashtree[] reducedHashTree,
            HashAlgorithm hashAlgorithm) {

        // Obtain a timestamp for the root hash value
        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        TimeStampRequest request = generator.generate(hashAlgorithm.getOid(), rootHash);
        ContentInfo timeStamp = timeStampingService.requestTimeStamp(request).toCMSSignedData().toASN1Structure();

        AlgorithmIdentifier identifier = new AlgorithmIdentifier(hashAlgorithm.getOid());

        // Create the archive timestamp
        ArchiveTimeStamp archiveTimeStamp = new ArchiveTimeStamp(identifier, reducedHashTree, timeStamp);
        return archiveTimeStamp;
    }

    /**
     * Verify that {@code contentToVerify} existed using the ArchiveTimeStamp according to the verification algorithm
     * described in RFC 4998 (https://datatracker.ietf.org/doc/html/rfc4998#section-4.3).
     */
    public boolean verifyArchiveTimeStamp(ArchiveTimeStamp archiveTimeStamp, byte[] contentToVerify,
            HashAlgorithm hashAlgorithm) {

        // 1. Calculate hash value h of the data object with hash algorithm H given in field digestAlgorithm of the
        // Archive Timestamp.
        byte[] h = CryptoUtils.hash(contentToVerify, hashAlgorithm);

        boolean hasHashTree = archiveTimeStamp.getHashTreeLeaf() != null;
        if (!hasHashTree) {
            return Arrays.equals(h, archiveTimeStamp.getTimeStampDigestValue());
        }

        // 2. Search for hash value h in the first list (partialHashtree) of reducedHashtree. If not present, terminate
        // verification process with negative result.
        if (!archiveTimeStamp.getHashTreeLeaf().containsHash(h)) {
            return false;
        }

        // 3. Concatenate the hash values of the actual list (partialHashtree) of hash values in binary ascending order
        // and calculate the hash value h' with algorithm H. This hash value h' MUST become a member of the next higher
        // list of hash values (from the next partialHashtree). Continue step 3 until a root hash value is calculated.
        for (int i = 0; i < archiveTimeStamp.getReducedHashTree().length - 1; i++) {
            byte[] concatenatedHashes = CryptoUtils
                    .sortAndFlatten(archiveTimeStamp.getReducedHashTree()[i].getValues());
            byte[] hPrime = CryptoUtils.hash(concatenatedHashes, hashAlgorithm);
            if (!archiveTimeStamp.getReducedHashTree()[i + 1].containsHash(hPrime)) {
                return false;
            }
        }

        // 4. Check timestamp. In case of a timestamp according to [RFC3161], the root hash value must correspond to
        // hashedMessage, and digestAlgorithm must correspond to hashAlgorithm field, both in messageImprint field of
        // timeStampToken. In case of other timestamp formats, the hash value and digestAlgorithm must also correspond
        // to their equivalent fields if they exist.
        TimeStampToken timeStampToken;
        try {
            timeStampToken = new TimeStampToken(archiveTimeStamp.getTimeStamp());
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse archive timestamp", e);
        }
        byte[] expectedRootHash = CryptoUtils.hash(
                CryptoUtils.sortAndFlatten(
                        archiveTimeStamp.getReducedHashTree()[archiveTimeStamp.getReducedHashTree().length - 1]
                                .getValues()),
                hashAlgorithm);
        // alternative: byte[] hashedMessage = result.getTimeStampDigestValue();
        byte[] hashedMessage = timeStampToken.getTimeStampInfo().getMessageImprintDigest();

        if (!Arrays.equals(hashedMessage, expectedRootHash)) {
            return false;
        }

        return true;
    }
}
