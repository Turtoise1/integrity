package com.example.merkletree.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import org.bouncycastle.asn1.tsp.ArchiveTimeStamp;
import org.bouncycastle.asn1.tsp.ArchiveTimeStampChain;
import org.bouncycastle.asn1.tsp.PartialHashtree;
import org.bouncycastle.tsp.TSPException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.example.merkletree.model.Composite;
import com.example.merkletree.model.HashAlgorithm;
import com.example.merkletree.model.MerkleTreeNode;
import com.example.merkletree.utils.TestCompositeUtils;

@SpringBootTest
class ArchiveTimeStampingServiceTest {

    @Autowired
    private ArchiveTimeStampingService archiveTimeStampingService;

    @Test
    public void callCreateArchiveTimeStamp() throws IOException {
        // Random test values
        Composite testComposite = TestCompositeUtils.generateTestComposite();
        Composite chosenDocument = TestCompositeUtils.pickRandomLeaf(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected descendant
        MerkleTreeNode chosenNode = tree.findDescendant(chosenDocument);
        byte[] rootHash = tree.getHash();
        PartialHashtree[] reducedTree = tree.getPathToDescendant(chosenNode.getHash());
        // Chosen node is a leaf node, so it should not equal the root hash
        assertNotNull(reducedTree);

        ArchiveTimeStamp result = archiveTimeStampingService.createArchiveTimeStamp(rootHash, reducedTree,
                hashAlgorithm);

        String algorithmResult = result.getDigestAlgorithm().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmResult);

        String algorithmIdentifierResult = result.getDigestAlgorithmIdentifier().getAlgorithm().toString();
        assertEquals(hashAlgorithm.getOid().toString(), algorithmIdentifierResult);

        PartialHashtree resultLeaf = result.getHashTreeLeaf();
        MerkleTreeNode parent = tree.findParent(chosenNode);
        PartialHashtree expectedLeaf = parent.getPathToDescendant(chosenNode.getHash())[0];
        assertEquals(expectedLeaf.toString(), resultLeaf.toString());
    }

    @Test
    public void testTimeStampRenewal() throws Exception {
        // Random test values
        Composite testComposite = TestCompositeUtils.generateTestComposite();
        Composite chosenDocument = TestCompositeUtils.pickRandomLeaf(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected ancestor
        MerkleTreeNode chosenNode = tree.findDescendant(chosenDocument);
        PartialHashtree[] reducedTree = tree.getPathToDescendant(chosenNode.getHash());

        ArchiveTimeStamp archiveTimeStamp = archiveTimeStampingService.createArchiveTimeStamp(tree.getHash(),
                reducedTree,
                hashAlgorithm);

        ArchiveTimeStampChain chain = new ArchiveTimeStampChain(archiveTimeStamp);

        // event: private key of time stamp unit is compromised

        ArchiveTimeStampChain updatedChain = archiveTimeStampingService.timeStampRenewal(chain, null);

        // event: hash algorithm used for timestamp renewal will become insecure soon

        archiveTimeStampingService.timeStampRenewal(updatedChain, HashAlgorithm.SHA512);

    }

    @Test
    public void verifyArchiveTimeStamp() throws IOException, TSPException {
        // Random test values
        Composite testComposite = TestCompositeUtils.generateTestComposite();
        Composite chosenDocument = TestCompositeUtils.pickRandomLeaf(testComposite);
        HashAlgorithm hashAlgorithm = HashAlgorithm.SHA256;

        // Generate hash tree
        MerkleTreeNode tree = new MerkleTreeNode(testComposite, hashAlgorithm);

        // Get the reduced tree to the randomly selected ancestor
        MerkleTreeNode chosenNode = tree.findDescendant(chosenDocument);
        PartialHashtree[] reducedTree = tree.getPathToDescendant(chosenNode.getHash());

        ArchiveTimeStamp result = archiveTimeStampingService.createArchiveTimeStamp(tree.getHash(), reducedTree,
                hashAlgorithm);

        assertEquals(true, archiveTimeStampingService.verifyArchiveTimeStamp(result,
                chosenDocument.getContent().getBytes(), hashAlgorithm));
    }

}
