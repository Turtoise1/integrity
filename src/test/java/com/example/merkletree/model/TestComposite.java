package com.example.merkletree.model;

import java.util.List;

public class TestComposite extends Composite {

    private String content = null;
    private final List<TestComposite> children;

    public TestComposite(List<TestComposite> children) {
        this.children = children;
        if (this.children == null || this.children.isEmpty()) {
            generateRandomContent();
        }
    }

    private void generateRandomContent() {
        int length = randomInt();
        for (int i = 0; i < length; i++) {
            content += String.valueOf(randomInt());
        }
    }

    private int randomInt() {
        return (int) (Math.random() * 100);
    }

    @Override
    public String getContent() {
        return content;
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Composite> getChildren() {
        return (List<Composite>) (List<?>) children;
    }
}
