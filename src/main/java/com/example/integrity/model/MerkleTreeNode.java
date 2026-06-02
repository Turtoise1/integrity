package com.example.integrity.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.tsp.PartialHashtree;

import com.example.integrity.utils.CryptoUtils;

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
     * Construct a merkle hash tree over the {@code composite} and its children. Generation is defined in
     * https://datatracker.ietf.org/doc/html/rfc4998#section-4.2
     * <ol>
     * <li>Recursively construct merkle tree nodes on the children of {@code composite}.</li>
     * <li>For each node:
     * <ol>
     * <li>If it has children, calculate a hash on the sorted concatenation of the hashes of all {@link MerkleTreeNode
     * 'child nodes'}.</li>
     * <li>If it has no children, calculate the hash of the {@link Composite#content}.</li>
     * </ol>
     * </li>
     * </ol>
     *
     * @param composite     The tree data to construct the hash tree over.
     * @param hashAlgorithm The {@link HashAlgorithm 'hash algorithm'} to use.
     */
    public MerkleTreeNode(Composite composite, HashAlgorithm hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        this.composite = composite;
        if (composite.getChildren().size() > 0) {
            if (composite.getContent() != null) {
                throw new RuntimeException(
                        "Composite must have either children or content, not both to build a Merkle tree");
            }
            for (Composite compChild : composite.getChildren()) {
                children.add(new MerkleTreeNode(compChild, hashAlgorithm));
            }
            calculateHashByChildren();
        } else {
            if (composite.getContent() == null) {
                throw new RuntimeException("Composite must have either children or content to build a Merkle tree");
            }
            calculateHashByContent();
        }
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
     * Search the descendants of this node for some node where {@link MerkleTreeNode#hash} matches the given hash.
     * Returns all nodes and their children that lie on the path as partial hashtrees. The path is returned in reverse
     * order, starting with the descendant node and ending with this node.
     *
     * @param descendantHash The hash to search for.
     * @return The list of partial hashtrees on the path from the ancestor node to this node, or {@code null} if not
     *         found. Also returns {@code null} if descendantHash is this node's hash.
     */
    public PartialHashtree[] getPathToDescendant(byte[] descendantHash) {
        PartialHashtree[] path = null;

        if (Arrays.equals(hash, descendantHash)) {
            // Method call was this.getPathToDescendant(this.hash) for which no hash tree can be constructed
            return null;
        }

        // recursion anchor: any child hash equals the descendant hash
        if (Arrays.stream(getChildHashes()).anyMatch(ch -> Arrays.equals(ch, descendantHash))) {
            path = new PartialHashtree[1];
            path[0] = new PartialHashtree(getChildHashes());
            return path;
        }

        // recursion step
        for (int i = 0; i < children.size(); i++) {
            MerkleTreeNode child = children.get(i);
            PartialHashtree[] childPath = child.getPathToDescendant(descendantHash);
            if (childPath != null) {
                path = new PartialHashtree[childPath.length + 1];
                path[childPath.length] = new PartialHashtree(getChildHashes());
                System.arraycopy(childPath, 0, path, 0, childPath.length);
                return path;
            }
        }

        // has no ancestor with the given hash
        return null;
    }

    /**
     * Try to find a descendant node that was built on the given composite.
     *
     * @param composite The composite to search in this tree.
     * @return The descendant node or {@code null} if not found.
     */
    public MerkleTreeNode findDescendant(Composite composite) {
        if (composite.equals(this.composite)) {
            return this;
        }

        for (MerkleTreeNode child : children) {
            MerkleTreeNode descendant = child.findDescendant(composite);
            if (descendant != null) {
                return descendant;
            }
        }

        return null;
    }

    /**
     * Returns the parent of {@code target} if included in the descendants of this merkle tree node.
     */
    public MerkleTreeNode findParent(MerkleTreeNode target) {
        if (target == null) {
            return null;
        }
        if (getChildren().contains(target)) {
            return this;
        }
        for (MerkleTreeNode child : getChildren()) {
            MerkleTreeNode parent = child.findParent(target);
            if (parent != null) {
                return parent;
            }
        }
        return null;
    }

    private byte[][] getChildHashes() {
        byte[][] childHashes = new byte[children.size()][];
        for (int i = 0; i < children.size(); i++) {
            childHashes[i] = children.get(i).getHash();
        }
        return childHashes;
    }

    /**
     * Calculate hash of {@link MerkleTreeNode#composite} content and add together with the hashes of all child nodes.
     * Sort and concatenate all these hashes and calculate the own hash from the result.
     */
    private void calculateHashByChildren() {
        byte[] concatenated = CryptoUtils.sortAndFlatten(getChildHashes());

        hash = CryptoUtils.hash(concatenated, hashAlgorithm);
    }

    /** Calculates the hash of the corresponding test composite content. */
    private void calculateHashByContent() {
        hash = CryptoUtils.hash(composite.getContent().getBytes(), hashAlgorithm);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass())
            return false;
        MerkleTreeNode other = (MerkleTreeNode) o;
        return hashCode() == other.hashCode();
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash);
    }
}
