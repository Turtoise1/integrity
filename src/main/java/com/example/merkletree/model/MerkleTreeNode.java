package com.example.merkletree.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.tsp.PartialHashtree;

import com.example.merkletree.utils.CryptoUtils;

import lombok.extern.slf4j.Slf4j;

/**
 * Used to construct a merkle hash tree over a {@link Composite 'test composite'}. See
 * {@link MerkleTreeNode#MerkleTreeNode(Composite, HashAlgorithm)}.
 */
@Slf4j
public class MerkleTreeNode {
    private byte[] hash;
    private Composite composite;
    private List<MerkleTreeNode> children = new ArrayList<>();
    private final HashAlgorithm hashAlgorithm;

    /**
     * Construct a merkle hash tree over the {@code composite} and its children:
     * <ol>
     * <li>Recursively construct merkle tree nodes on the children of {@code composite}.</li>
     * <li>Calculate a hash on the sorted concatenation of the hashes of all {@link MerkleTreeNode 'child nodes'}
     * together with the hash of {@code composite}.</li>
     * </ol>
     *
     * @param composite     The tree data to construct the hash tree over.
     * @param hashAlgorithm The {@link HashAlgorithm 'hash algorithm'} to use.
     */
    public MerkleTreeNode(Composite composite, HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        this.composite = composite;
        for (Composite compChild : composite.getChildren()) {
            children.add(new MerkleTreeNode(compChild, hashAlgorithm));
        }
        calculateHash();
    }

    /**
     * @return the hash calculated in the {@link MerkleTreeNode#MerkleTreeNode(Composite, HashAlgorithm)
     *         'constructor'}.
     */
    public byte[] getHash() {
        return hash;
    }

    /**
     *
     * @return the list of all {@link MerkleTreeNode 'child nodes'} calculated in the
     *         {@link MerkleTreeNode#MerkleTreeNode(Composite, HashAlgorithm) 'constructor'}.
     */
    public List<MerkleTreeNode> getChildren() {
        return children;
    }

    /**
     * Search the ancestors of this node for some node where {@link MerkleTreeNode#hash} matches the given hash. Returns
     * all nodes and their children that lie on the path as partial hashtrees. The path is returned in reverse order,
     * starting with the ancestor node and ending with this node.
     *
     * @param ancestorHash The hash to search for.
     * @return The list of partial hashtrees on the path from the ancestor node to this node, or {@code null} if not
     *         found.
     */
    public PartialHashtree[] getPathFromAncestor(byte[] ancestorHash) {
        PartialHashtree[] path = null;

        // recursion anchor
        if (Arrays.equals(hash, ancestorHash)) {
            path = new PartialHashtree[1];
            path[0] = new PartialHashtree(getHashes());
            return path;
        }

        // recursion step
        for (int i = 0; i < children.size(); i++) {
            MerkleTreeNode child = children.get(i);
            PartialHashtree[] childPath = child.getPathFromAncestor(ancestorHash);
            if (childPath != null) {
                path = new PartialHashtree[childPath.length + 1];
                path[childPath.length] = new PartialHashtree(getHashes());
                System.arraycopy(childPath, 0, path, 0, childPath.length);
                return path;
            }
        }

        // has no ancestor with the given hash
        return null;
    }

    /**
     * Try to find an ancestor node that was built on the given composite.
     *
     * @param composite The composite to search in this tree.
     * @return The ancestor node or {@code null} if not found.
     */
    public MerkleTreeNode findAncestor(Composite composite) {
        if (composite.equals(this.composite)) {
            return this;
        }

        for (MerkleTreeNode child : children) {
            MerkleTreeNode ancestor = child.findAncestor(composite);
            if (ancestor != null) {
                return ancestor;
            }
        }

        return null;
    }

    /**
     * Calculates the hash of the corresponding test composite content. Returns it together with the hashes of all child
     * merkle tree nodes.
     */
    private byte[][] getHashes() {
        byte[][] hashes = new byte[children.size() + 1][];
        for (int i = 0; i < children.size(); i++) {
            hashes[i] = children.get(i).getHash();
        }
        hashes[children.size()] = CryptoUtils.hash(composite.getContent().getBytes(), hashAlgorithm);
        return hashes;
    }

    /**
     * Calculate hash of {@link MerkleTreeNode#composite} content and add together with the hashes of all child nodes.
     * Sort and concatenate all these hashes and calculate the own hash from the result.
     *
     * @param childrenHashes The hashes of all child merkle tree nodes.
     */
    private void calculateHash() {
        byte[] allHashes = CryptoUtils.sortAndFlatten(getHashes());

        hash = CryptoUtils.hash(allHashes, hashAlgorithm);
    }
}
