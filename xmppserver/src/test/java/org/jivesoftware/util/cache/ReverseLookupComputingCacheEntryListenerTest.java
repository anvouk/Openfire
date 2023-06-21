/*
 * Copyright (C) 2023 Ignite Realtime Foundation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.util.cache;

import org.jivesoftware.openfire.cluster.NodeID;
import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ReverseLookupComputingCacheEntryListenerTest {

    /**
     * Simulates a scenario where one cluster node adds an entry to an otherwise empty cache.
     */
    @Test
    public void testAdd() throws Exception
    {
        // Setup text fixture, Simulating things for a cache with this signature: Cache<String, Set<NodeID>> cache;
        final Map<NodeID, Set<String>> reverseLookupMap = new HashMap<>();
        final Function<Set<NodeID>, Set<NodeID>> deducer = nodeIDS -> nodeIDS;
        final ReverseLookupComputingCacheEntryListener<String, Set<NodeID>> listener = new ReverseLookupComputingCacheEntryListener<>(reverseLookupMap, deducer);
        final NodeID clusterNode = NodeID.getInstance(UUID.randomUUID().toString().getBytes());

        // Execute system under test.
        listener.entryAdded("somekey", Collections.singleton(clusterNode), clusterNode);

        // Assert result
        assertTrue(reverseLookupMap.containsKey(clusterNode));
        assertTrue(reverseLookupMap.get(clusterNode).contains("somekey"));
    }

    /**
     * Simulates a scenario where one cluster node adds an entry to an otherwise empty cache, followed by another
     * cluster node updating that entry, adding itself as another 'owner' of the entry. In this scenario, the
     * event listeners are fired in the same order as the order in which the insertions occur. Due to the asynchronous
     * behavior, this is not guaranteed to occur (see #testUpdateEventsInWrongOrder).
     */
    @Test
    public void testUpdate() throws Exception
    {
        // Setup text fixture, Simulating things for a cache with this signature: Cache<String, Set<NodeID>> cache;
        final Map<NodeID, Set<String>> reverseLookupMap = new HashMap<>();
        final Function<HashSet<NodeID>, Set<NodeID>> deducer = nodeIDS -> nodeIDS;
        final ReverseLookupComputingCacheEntryListener<String, HashSet<NodeID>> listener = new ReverseLookupComputingCacheEntryListener<>(reverseLookupMap, deducer);
        final NodeID clusterNodeA = NodeID.getInstance(UUID.randomUUID().toString().getBytes());
        final NodeID clusterNodeB = NodeID.getInstance(UUID.randomUUID().toString().getBytes());

        // Execute system under test.
        listener.entryAdded("somekey", new HashSet<>(Arrays.asList(clusterNodeA)), clusterNodeA);
        listener.entryUpdated("somekey", new HashSet<>(Arrays.asList(clusterNodeA)), new HashSet<>(Arrays.asList(clusterNodeA, clusterNodeB)), clusterNodeB );

        // Assert result
        assertTrue(reverseLookupMap.containsKey(clusterNodeA));
        assertTrue(reverseLookupMap.get(clusterNodeA).contains("somekey"));
        assertTrue(reverseLookupMap.containsKey(clusterNodeB));
        assertTrue(reverseLookupMap.get(clusterNodeB).contains("somekey"));
    }

    /**
     * Simulates a scenario where one cluster node adds an entry to an otherwise empty cache, followed by another
     * cluster node updating that entry, adding itself as another 'owner' of the entry, where the events that are
     * generated by these actions arrive in the reversed order (which, as this is an async operation, can occur).
     */
    @Test
    public void testUpdateEventsInWrongOrder() throws Exception
    {
        // Setup text fixture, Simulating things for a cache with this signature: Cache<String, Set<NodeID>> cache;
        final Map<NodeID, Set<String>> reverseLookupMap = new HashMap<>();
        final Function<HashSet<NodeID>, Set<NodeID>> deducer = nodeIDS -> nodeIDS;
        final ReverseLookupComputingCacheEntryListener<String, HashSet<NodeID>> listener = new ReverseLookupComputingCacheEntryListener<>(reverseLookupMap, deducer);
        final NodeID clusterNodeA = NodeID.getInstance(UUID.randomUUID().toString().getBytes());
        final NodeID clusterNodeB = NodeID.getInstance(UUID.randomUUID().toString().getBytes());

        // Execute system under test.
        listener.entryUpdated("somekey", new HashSet<>(Arrays.asList(clusterNodeA)), new HashSet<>(Arrays.asList(clusterNodeA, clusterNodeB)), clusterNodeB);
        listener.entryAdded("somekey", new HashSet<>(Arrays.asList(clusterNodeA)), clusterNodeA);

        // Assert result
        assertTrue(reverseLookupMap.containsKey(clusterNodeA));
        assertTrue(reverseLookupMap.get(clusterNodeA).contains("somekey"));
        assertTrue(reverseLookupMap.containsKey(clusterNodeB));
        assertTrue(reverseLookupMap.get(clusterNodeB).contains("somekey"));
    }
}
