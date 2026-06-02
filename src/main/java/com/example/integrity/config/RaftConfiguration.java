package com.example.integrity.config;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import com.example.integrity.filestore.commands.Server;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Configuration
@Slf4j
public class RaftConfiguration {

    @Value("${raft.group.id}")
    private String raftGroupId;

    @Value("${raft.peers}")
    private String peers;

    @Value("${raft.storage.base}")
    private String storageBaseDir;

    private List<Server> servers = new ArrayList<>();

    @PostConstruct
    public void startServers() {

        log.info("[{}: Peers {}] Starting Raft servers...", raftGroupId, peers);

        String[] peerAddresses = peers.split(",");

        for (int i = 0; i < peerAddresses.length; i++) {
            String peer = peerAddresses[i];
            String[] parts = peer.split(":");
            String id = parts[0];

            File storageDir = new File(storageBaseDir + "/" + id);
            storageDir.mkdirs();

            List<File> storageDirs = new ArrayList<>();
            storageDirs.add(storageDir);

            log.info("Starting Raft server {} on port {}", id, parts[2]);
            Server server = new Server(raftGroupId, peers, id, storageDirs, null, null, null, null);
            servers.add(server);

            new Thread(() -> {
                try {
                    server.run();
                } catch (Exception e) {
                    log.error("Server {} failed", id, e);
                }
            }).start();

            log.info("Started Raft server {} on port {}", id, parts[2]);
        }

        // Give servers time to start
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public String getPeers() {
        return peers;
    }

    public String getRaftGroupId() {
        return raftGroupId;
    }
}
