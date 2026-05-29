package com.example.merkletree.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.example.merkletree.model.Composite;
import com.example.merkletree.model.HashAlgorithm;
import com.example.merkletree.model.MerkleTreeNode;
import com.example.merkletree.service.ArchiveTimeStampingService;
import com.example.merkletree.utils.CryptoUtils;
import com.example.merkletree.utils.TestCompositeUtils;

@SpringBootTest
class ArchiveTimeStampingServiceTest {

    @Autowired
    private ArchiveTimeStampingService archiveTimeStampingService;

    @Test
    public void callCreateArchiveTimeStamp() throws IOException {
        // Random test values
        Composite testComposite = TestCompositeUtils.generateTestComposite();
        Composite chosenDocument = TestCompositeUtils.pickRandomAncestor(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected ancestor
        MerkleTreeNode chosenNode = tree.findAncestor(chosenDocument);
        byte[] rootHash = tree.getHash();
        PartialHashtree[] reducedTree = tree.getPathFromAncestor(chosenNode.getHash());

        ArchiveTimeStamp result = archiveTimeStampingService.createArchiveTimeStamp(rootHash, reducedTree,
                hashAlgorithm);

        String algorithmResult = result.getDigestAlgorithm().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmResult);

        String algorithmIdentifierResult = result.getDigestAlgorithmIdentifier().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmIdentifierResult);

        PartialHashtree resultLeaf = result.getHashTreeLeaf();
        PartialHashtree expectedLeaf = chosenNode.getPathFromAncestor(chosenNode.getHash())[0];
        assertEquals(expectedLeaf.toString(), resultLeaf.toString());
    }

    @Test
    public void testTimeStampRenewal() throws Exception {
        // Random test values
        Composite testComposite = TestCompositeUtils.generateTestComposite();
        Composite chosenDocument = TestCompositeUtils.pickRandomAncestor(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected ancestor
        MerkleTreeNode chosenNode = tree.findAncestor(chosenDocument);
        PartialHashtree[] reducedTree = tree.getPathFromAncestor(chosenNode.getHash());

        ArchiveTimeStamp archiveTimeStamp = archiveTimeStampingService.createArchiveTimeStamp(tree.getHash(),
                reducedTree,
                hashAlgorithm);

        ArchiveTimeStampChain chain = new ArchiveTimeStampChain(archiveTimeStamp);

        // event: private key of time stamp unit is compromised

        ArchiveTimeStampChain updatedChain = archiveTimeStampingService.timeStampRenewal(chain, null);

        // event: hash algorithm used for timestamp renewal will become insecure soon

        archiveTimeStampingService.timeStampRenewal(updatedChain, HashAlgorithm.SHA512);

    }

    /**
     * Verify that {@code chosenDocument} existed using the ArchiveTimeStamp according to the verification algorithm
     * described in RFC 4998 (https://datatracker.ietf.org/doc/html/rfc4998#section-4.3).
     */
    @Test
    public void verifyArchiveTimeStamp() throws IOException, TSPException {
        // Random test values
        Composite testComposite = TestCompositeUtils.generateTestComposite();
        Composite chosenDocument = TestCompositeUtils.pickRandomAncestor(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected ancestor
        MerkleTreeNode chosenNode = tree.findAncestor(chosenDocument);
        PartialHashtree[] reducedTree = tree.getPathFromAncestor(chosenNode.getHash());

        ArchiveTimeStamp result = archiveTimeStampingService.createArchiveTimeStamp(tree.getHash(), reducedTree,
                hashAlgorithm);

        // 1. Calculate hash value h of the data object with hash algorithm H given in field digestAlgorithm of the
        // Archive Timestamp.
        byte[] h = CryptoUtils.hash(chosenDocument.getContent().getBytes(), hashAlgorithm);

        // 2. Search for hash value h in the first list (partialHashtree) of reducedHashtree. If not present, terminate
        // verification process with negative result.
        assertEquals(true, result.getHashTreeLeaf().containsHash(h));

        // 3. Concatenate the hash values of the actual list (partialHashtree) of hash values in binary ascending order
        // and calculate the hash value h' with algorithm H. This hash value h' MUST become a member of the next higher
        // list of hash values (from the next partialHashtree). Continue step 3 until a root hash value is calculated.
        for (int i = 0; i < result.getReducedHashTree().length - 1; i++) {
            byte[] concatenatedHashes = CryptoUtils.sortAndFlatten(result.getReducedHashTree()[i].getValues());
            byte[] hPrime = CryptoUtils.hash(concatenatedHashes, hashAlgorithm);
            assertEquals(true, result.getReducedHashTree()[i + 1].containsHash(hPrime));
        }

        // 4. Check timestamp. In case of a timestamp according to [RFC3161], the root hash value must correspond to
        // hashedMessage, and digestAlgorithm must correspond to hashAlgorithm field, both in messageImprint field of
        // timeStampToken. In case of other timestamp formats, the hash value and digestAlgorithm must also correspond
        // to their equivalent fields if they exist.
        TimeStampToken timeStampToken = new TimeStampToken(
                result.getTimeStamp());
        byte[] expectedRootHash = CryptoUtils.hash(
                CryptoUtils.sortAndFlatten(
                        result.getReducedHashTree()[result.getReducedHashTree().length - 1].getValues()),
                hashAlgorithm);
        // alternative: byte[] hashedMessage = result.getTimeStampDigestValue();
        byte[] hashedMessage = timeStampToken.getTimeStampInfo().getMessageImprintDigest();
        assertEquals(Arrays.toString(hashedMessage), Arrays.toString(expectedRootHash));

        String messageImprintAlgOID = timeStampToken.getTimeStampInfo().getMessageImprintAlgOID().toString();
        String digestAlgOID = result.getDigestAlgorithm().getAlgorithm().toString();
        assertEquals(messageImprintAlgOID, digestAlgOID);
    }

}
