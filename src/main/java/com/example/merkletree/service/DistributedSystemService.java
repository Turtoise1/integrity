package com.example.merkletree.service;

import com.example.merkletree.filestore.FileStoreClient;
import org.apache.ratis.RaftConfigKeys;
import org.apache.ratis.client.RaftClient;
import org.apache.ratis.client.RaftClientConfigKeys;
import org.apache.ratis.conf.RaftProperties;
import org.apache.ratis.datastream.SupportedDataStreamType;
import org.apache.ratis.grpc.GrpcConfigKeys;
import org.apache.ratis.grpc.GrpcFactory;
import org.apache.ratis.protocol.ClientId;
import org.apache.ratis.protocol.RaftGroup;
import org.apache.ratis.protocol.RaftGroupId;
import org.apache.ratis.protocol.RaftPeer;
import org.apache.ratis.rpc.SupportedRpcType;
import org.apache.ratis.server.RaftServerConfigKeys;
import org.apache.ratis.thirdparty.com.google.protobuf.ByteString;
import org.apache.ratis.util.SizeInBytes;
import org.apache.ratis.util.TimeDuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class DistributedSystemService {

    @Autowired
    private DocumentService documentService;

    private static final String RAFT_GROUP_ID = "demoRaftGroup123";
    private static final String PEERS = "n0:127.0.0.1:6000,n1:127.0.0.1:6001,n2:127.0.0.1:6002";

    private final ConcurrentHashMap<String, Long> fileMetadata = new ConcurrentHashMap<>();

    public void distribute(String path) throws IOException {
        File file = documentService.getFile(path);
        FileStoreClient client = getClient();

        String fileName = file.getName().toString();
        long fileSize = Files.size(file.toPath());

        // Read file content in chunks for large files
        byte[] fileContent = documentService.getFileContent(path);
        ByteBuffer buffer = ByteBuffer.wrap(fileContent);

        // Write file to distributed storage
        // The write method takes: path, offset, close, buffer, sync
        client.write(fileName, 0, false, buffer, false);

        // Track file metadata for listing
        fileMetadata.put(fileName, fileSize);
    }

    public List<String> listData() {
        return new ArrayList<>(fileMetadata.keySet());
    }

    public byte[] retrieve(String filePath) throws IOException {
        FileStoreClient client = getClient();

        String fileName = Path.of(filePath).getFileName().toString();
        Long fileSize = fileMetadata.get(fileName);

        if (fileSize == null) {
            return null;
        }

        // Read the entire file
        ByteString data = client.read(fileName, 0, fileSize);
        return data.toByteArray();
    }
}
