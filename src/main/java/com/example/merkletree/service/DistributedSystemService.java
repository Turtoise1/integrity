package com.example.merkletree.service;

import com.example.merkletree.config.RaftConfiguration;
import com.example.merkletree.filestore.FileStoreClient;

import jakarta.annotation.PreDestroy;

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

    private final RaftConfiguration raftConfig;
    private FileStoreClient fileStoreClient;
    private final ConcurrentHashMap<String, Long> fileMetadata = new ConcurrentHashMap<>();

    public DistributedSystemService(RaftConfiguration raftConfig) {
        this.raftConfig = raftConfig;
    }

    private synchronized FileStoreClient getClient() {
        if (fileStoreClient == null) {
            fileStoreClient = createFileStoreClient();
        }
        return fileStoreClient;
    }

    private FileStoreClient createFileStoreClient() {
        int raftSegmentPreallocatedSize = 1024 * 1024 * 1024;
        RaftProperties raftProperties = new RaftProperties();
        RaftConfigKeys.Rpc.setType(raftProperties, SupportedRpcType.GRPC);
        GrpcConfigKeys.setMessageSizeMax(raftProperties,
                SizeInBytes.valueOf(raftSegmentPreallocatedSize));
        RaftServerConfigKeys.Log.Appender.setBufferByteLimit(raftProperties,
                SizeInBytes.valueOf(raftSegmentPreallocatedSize));
        RaftServerConfigKeys.Log.setWriteBufferSize(raftProperties,
                SizeInBytes.valueOf(raftSegmentPreallocatedSize));
        RaftServerConfigKeys.Log.setPreallocatedSize(raftProperties,
                SizeInBytes.valueOf(raftSegmentPreallocatedSize));
        RaftServerConfigKeys.Log.setSegmentSizeMax(raftProperties,
                SizeInBytes.valueOf(1 * 1024 * 1024 * 1024L));
        RaftConfigKeys.DataStream.setType(raftProperties, SupportedDataStreamType.NETTY);

        RaftServerConfigKeys.Log.setSegmentCacheNumMax(raftProperties, 2);

        RaftClientConfigKeys.Rpc.setRequestTimeout(raftProperties,
                TimeDuration.valueOf(50000, TimeUnit.MILLISECONDS));
        RaftClientConfigKeys.Async.setOutstandingRequestsMax(raftProperties, 1000);

        RaftPeer[] peers = parsePeers(raftConfig.getPeers());
        RaftGroup raftGroup = RaftGroup.valueOf(
                RaftGroupId.valueOf(ByteString.copyFromUtf8(raftConfig.getRaftGroupId())),
                peers);

        RaftClient.Builder builder = RaftClient.newBuilder().setProperties(raftProperties);
        builder.setRaftGroup(raftGroup);
        builder.setClientRpc(
                new GrpcFactory(new org.apache.ratis.conf.Parameters())
                        .newRaftClientRpc(ClientId.randomId(), raftProperties));
        builder.setPrimaryDataStreamServer(peers[0]);
        RaftClient client = builder.build();

        return new FileStoreClient(client);
    }

    private RaftPeer[] parsePeers(String peers) {
        String[] peerAddresses = peers.split(",");
        RaftPeer[] result = new RaftPeer[peerAddresses.length];
        for (int i = 0; i < peerAddresses.length; i++) {
            String[] addressParts = peerAddresses[i].split(":");
            RaftPeer.Builder builder = RaftPeer.newBuilder();
            builder.setId(addressParts[0]).setAddress(addressParts[1] + ":" + addressParts[2]);
            if (addressParts.length >= 4) {
                builder.setDataStreamAddress(addressParts[1] + ":" + addressParts[3]);
                if (addressParts.length >= 5) {
                    builder.setClientAddress(addressParts[1] + ":" + addressParts[4]);
                    if (addressParts.length >= 6) {
                        builder.setAdminAddress(addressParts[1] + ":" + addressParts[5]);
                    }
                }
            }
            result[i] = builder.build();
        }
        return result;
    }

    public void distribute(String path) throws IOException {
        File file = documentService.getFile(path);
        Path filePath = file.toPath();
        if (!Files.exists(filePath)) {
            throw new IOException("File not found: " + path);
        }

        FileStoreClient client = getClient();

        String fileName = filePath.getFileName().toString();
        long fileSize = Files.size(filePath);

        // Read file content
        byte[] fileContent = Files.readAllBytes(filePath);
        ByteBuffer buffer = ByteBuffer.wrap(fileContent);

        // Write file to distributed storage
        client.write(fileName, 0, true, buffer, false);

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

    @PreDestroy
    public void cleanup() throws IOException {
        if (fileStoreClient != null) {
            fileStoreClient.close();
        }
    }
}
