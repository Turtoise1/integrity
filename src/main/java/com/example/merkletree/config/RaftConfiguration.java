package com.example.merkletree.config;

import org.apache.ratis.conf.RaftProperties;
import org.apache.ratis.protocol.RaftGroup;
import org.apache.ratis.protocol.RaftGroupId;
import org.apache.ratis.protocol.RaftPeer;
import org.apache.ratis.protocol.RaftPeerId;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
public class RaftConfiguration {

    @Value("${raft.group.id:integrity-group}")
    private String groupIdString;

    @Value("${raft.peers:localhost:8000,localhost:8001,localhost:8002}")
    private String[] peerAddresses;

    @Bean
    public RaftGroup raftGroup() {
        List<RaftPeer> peers = new ArrayList<>();
        for (int i = 0; i < peerAddresses.length; i++) {
            String address = peerAddresses[i];
            RaftPeerId peerId = RaftPeerId.valueOf(address);
            peers.add(RaftPeer.newBuilder()
                    .setId(peerId)
                    .setAddress(address)
                    .build());
        }
        
        // Create a UUID from the group ID string
        UUID uuid = UUID.nameUUIDFromBytes(groupIdString.getBytes());
        RaftGroupId raftGroupId = RaftGroupId.valueOf(uuid);
        
        return RaftGroup.valueOf(raftGroupId, peers);
    }

    @Bean
    public RaftProperties raftProperties() {
        RaftProperties properties = new RaftProperties();
        
        // Set state machine thread counts
        properties.setInt("example.filestore.statemachine.write.thread.num", 1);
        properties.setInt("example.filestore.statemachine.read.thread.num", 1);
        properties.setInt("example.filestore.statemachine.commit.thread.num", 1);
        properties.setInt("example.filestore.statemachine.delete.thread.num", 1);
        
        return properties;
    }
}
