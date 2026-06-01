package com.example.merkletree.model;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class FileComposite extends Composite {

    private List<FileComposite> children = new ArrayList<>();
    private File file;

    public FileComposite(File file) {
        this.file = file;
        if (file.isDirectory()) {
            children = List.of(file.listFiles()).stream().map(FileComposite::new).toList();
        }
    }

    /**
     * Returns the content of the underlying file as a string using the default charset.
     * Returns {@code null} if the file is a directory.
     */
    @Override
    public String getContent() {
        if (file.isDirectory()) {
            return null;
        }
        try {
            return new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
        } catch (IOException e) {
            throw new RuntimeException("Failed to read content of " + file.getName(), e);
        }
    }

    /**
     * Returns the name of the underlying file.
     */
    public String getName() {
        return file.getName();
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Composite> getChildren() {
        return (List<Composite>) (List<?>) children;
    }

}
