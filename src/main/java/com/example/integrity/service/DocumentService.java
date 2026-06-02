package com.example.integrity.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import jakarta.servlet.http.Part;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class DocumentService {

    @Value("${documents.folder}")
    private String DOCUMENTS_FOLDER;

    public List<String> listPaths() {
        Path root = Path.of(DOCUMENTS_FOLDER);
        try {
            return Files.walk(root)
                    .filter(path -> !path.equals(root))
                    .map(path -> root.relativize(path).toString())
                    .toList();
        } catch (IOException e) {
            throw new RuntimeException("Could not list paths", e);
        }
    }

    public void acceptDocuments(Collection<Part> parts) throws IOException {
        for (var part : parts) {

            // The name of the file is the relative path of the file in the client folder
            // Convert the client path separator to the server file path separator.
            String fileName = FilenameUtils.separatorsToSystem(part.getSubmittedFileName());

            // Resolve the absolute path to the file based on the public folder
            Path file = Path.of(DOCUMENTS_FOLDER).resolve(fileName);

            // Try to create the folder where the file is located
            if (Files.notExists(file.getParent())) {
                Files.createDirectories(file.getParent());
            }

            // Write data to file
            try (var inputStream = part.getInputStream()) {
                Files.copy(inputStream, file, StandardCopyOption.REPLACE_EXISTING);
            }

            log.info("write file: [{}] {}", part.getSize(), file);
        }

    }

    public byte[] getFileContent(String path) {
        try {
            return Files.readAllBytes(Path.of(DOCUMENTS_FOLDER + path));
        } catch (IOException e) {
            throw new RuntimeException("Could not read file content", e);
        }
    }

    public File getFile(String path) {
        return new File(DOCUMENTS_FOLDER + path);
    }

    public List<DSSDocument> getDocuments(String path) {
        // Create a list of documents to sign
        List<DSSDocument> documentsToSign = new ArrayList<>();

        // Add all files from a folder (recursively)
        File file = new File(DOCUMENTS_FOLDER + path);

        if (file.isDirectory()) {
            collectRecursive(file, file, documentsToSign);
        } else {
            FileDocument doc = new FileDocument(file);
            documentsToSign.add(doc);
        }

        return documentsToSign;
    }

    private void collectRecursive(File root, File current, List<DSSDocument> docs) {
        for (File file : current.listFiles()) {
            if (file.isDirectory()) {
                collectRecursive(root, file, docs);
            } else {
                collectFile(root, file, docs);
            }
        }
    }

    private void collectFile(File root, File file, List<DSSDocument> docs) {
        FileDocument doc = new FileDocument(file);
        String relativePath = root.toPath().relativize(file.toPath()).toString();
        doc.setName(relativePath);
        docs.add(doc);
    }

}
