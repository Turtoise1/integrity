package com.example.integrity.model;

import java.util.List;

/**
 * Represents a composite node. For merkle trees, only the leaf nodes contain content, while other nodes are composite
 * nodes with children.
 */
public abstract class Composite {

    /** For leaf nodes, returns the content of the composite. For other nodes, returns {@code null}. */
    public abstract String getContent();

    /** Returns the children of the composite. For leaf nodes, returns an empty list. */
    public abstract List<Composite> getChildren();

}
