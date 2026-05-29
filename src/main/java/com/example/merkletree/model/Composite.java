package com.example.merkletree.model;

import java.util.List;

public abstract class Composite {

    public abstract String getContent();

    public abstract List<Composite> getChildren();

}
