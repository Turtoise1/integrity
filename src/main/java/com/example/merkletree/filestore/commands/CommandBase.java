/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.merkletree.filestore.commands;

import org.apache.ratis.protocol.RaftPeer;
import org.apache.ratis.protocol.RaftPeerId;
import org.apache.ratis.protocol.RoutingTable;

import java.util.Collection;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Base subcommand class which includes the basic raft properties.
 */
public abstract class CommandBase {

    /** Raft group identifier */
    private String raftGroupId = "demoRaftGroup123";

    /** Raft peers (format: name:host:port:dataStreamPort:clientPort:adminPort,...) */
    private String peers;

    /**
     * Constructs a CommandBase with the given raft group id and peers.
     *
     * @param raftGroupId the optional raft group id
     * @param peers       the raft peers (format: name:host:port:dataStreamPort:clientPort:adminPort,...)
     */
    public CommandBase(String raftGroupId, String peers) {
        if (raftGroupId != null) {
            this.raftGroupId = raftGroupId;
        }
        if (this.peers == null) {
            throw new RuntimeException("peers must be specified");
        }
        this.peers = peers;
    }

    public static RaftPeer[] parsePeers(String peers) {
        return Stream.of(peers.split(",")).map(address -> {
            String[] addressParts = address.split(":");
            if (addressParts.length < 3) {
                throw new IllegalArgumentException(
                        "Raft peer " + address + " is not a legitimate format. "
                                + "(format: name:host:port:dataStreamPort:clientPort:adminPort)");
            }
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
            return builder.build();
        }).toArray(RaftPeer[]::new);
    }

    public RaftPeer[] getPeers() {
        return parsePeers(peers);
    }

    public RaftPeer getPrimary() {
        return parsePeers(peers)[0];
    }

    public abstract void run() throws Exception;

    public String getRaftGroupId() {
        return raftGroupId;
    }

    public RoutingTable getRoutingTable(Collection<RaftPeer> raftPeers, RaftPeer primary) {
        RoutingTable.Builder builder = RoutingTable.newBuilder();
        RaftPeer previous = primary;
        for (RaftPeer peer : raftPeers) {
            if (peer.equals(primary)) {
                continue;
            }
            builder.addSuccessor(previous.getId(), peer.getId());
            previous = peer;
        }

        return builder.build();
    }

    /**
     * @return the peer with the given id if it is in this group; otherwise, return null.
     */
    public RaftPeer getPeer(RaftPeerId raftPeerId) {
        Objects.requireNonNull(raftPeerId, "raftPeerId == null");
        for (RaftPeer p : getPeers()) {
            if (raftPeerId.equals(p.getId())) {
                return p;
            }
        }
        throw new IllegalArgumentException(
                "Raft peer id " + raftPeerId + " is not part of the raft group definitions " +
                        this.peers);
    }
}
