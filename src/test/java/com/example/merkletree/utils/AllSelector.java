package com.example.merkletree.utils;

import org.bouncycastle.util.Selector;

/** Selector selecting all objects. */
public class AllSelector<T extends Object> implements Selector<T> {

    @Override
    public boolean match(T obj) {
        return true;
    }

    @Override
    public Object clone() {
        return this;
    }

}
