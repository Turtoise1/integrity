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
package com.example.integrity.utils;

import org.apache.ratis.protocol.RaftPeer;
import org.apache.ratis.protocol.RaftPeerId;
import org.apache.ratis.protocol.RoutingTable;

import java.util.Collection;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Utility class for file store operations.
 */
public class FileStoreUtils {

    /** Default raft group identifier */
    public static final String DEFAULT_RAFT_GROUP_ID = "demoRaftGroup123";

    /**
     * Parses a comma-separated string of peer addresses into RaftPeer objects.
     *
     * @param peers the peer addresses (format: name:host:port:dataStreamPort:clientPort:adminPort,...)
     * @return array of RaftPeer objects
     */
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

    /**
     * Gets the primary peer from an array of peers.
     *
     * @param peers array of RaftPeer objects
     * @return the first peer (primary)
     */
    public static RaftPeer getPrimary(RaftPeer[] peers) {
        if (peers == null || peers.length == 0) {
            throw new IllegalArgumentException("peers must be specified and non-empty");
        }
        return peers[0];
    }

    /**
     * Gets the peer with the given id from an array of peers.
     *
     * @param peers      string of peers
     * @param raftPeerId the peer id to find
     * @return the peer with the given id
     * @throws IllegalArgumentException if the peer id is not found
     */
    public static RaftPeer getPeer(String peers, RaftPeerId raftPeerId) {
        Objects.requireNonNull(raftPeerId, "raftPeerId == null");
        if (peers == null) {
            throw new IllegalArgumentException("peers must be specified");
        }
        for (RaftPeer p : parsePeers(peers)) {
            if (raftPeerId.equals(p.getId())) {
                return p;
            }
        }
        throw new IllegalArgumentException(
                "Raft peer id " + raftPeerId + " is not part of the raft group definitions");
    }

    /**
     * Creates a routing table from a collection of raft peers and a primary peer.
     *
     * @param raftPeers the collection of raft peers
     * @param primary   the primary peer
     * @return the routing table
     */
    public static RoutingTable getRoutingTable(Collection<RaftPeer> raftPeers, RaftPeer primary) {
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
}
