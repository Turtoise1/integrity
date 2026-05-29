package com.example.merkletree.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import com.example.merkletree.model.Composite;
import com.example.merkletree.model.TestComposite;

public class TestCompositeUtils {

    public static Composite generateTestComposite() {

        List<TestComposite> leftLeftChildren = new ArrayList<>();
        leftLeftChildren.add(new TestComposite(new ArrayList<>()));
        leftLeftChildren.add(new TestComposite(new ArrayList<>()));
        TestComposite leftLeft = new TestComposite(leftLeftChildren);

        List<TestComposite> rightChildren = new ArrayList<>();
        rightChildren.add(new TestComposite(new ArrayList<>()));
        rightChildren.add(new TestComposite(new ArrayList<>()));
        TestComposite right = new TestComposite(rightChildren);

        List<TestComposite> leftChildren = new ArrayList<>();
        leftChildren.add(leftLeft);
        leftChildren.add(new TestComposite(new ArrayList<>()));
        TestComposite left = new TestComposite(leftChildren);

        List<TestComposite> rootChildren = new ArrayList<>();
        rootChildren.add(left);
        rootChildren.add(right);
        rootChildren.add(new TestComposite(new ArrayList<>()));
        TestComposite root = new TestComposite(rootChildren);

        return root;
    }

    public static Composite pickRandomAncestor(Composite input) {
        List<Composite> ancestors = flatten(input);
        return ancestors.get(ThreadLocalRandom.current().nextInt(ancestors.size()));
    }

    private static List<Composite> flatten(Composite input) {
        List<Composite> flattened = new ArrayList<>();
        flattened.add(input);
        for (Composite child : input.getChildren()) {
            flattened.addAll(flatten(child));
        }
        return flattened;
    }

}
