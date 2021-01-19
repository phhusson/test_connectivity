/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.networkstack.tethering.apishim.common;

import android.util.SparseArray;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.networkstack.tethering.BpfCoordinator.Dependencies;
import com.android.networkstack.tethering.BpfCoordinator.Ipv6ForwardingRule;
import com.android.networkstack.tethering.TetherStatsValue;

/**
 * Bpf coordinator class for API shims.
 */
public abstract class BpfCoordinatorShim {
    /**
     * Get BpfCoordinatorShim object by OS build version.
     */
    @NonNull
    public static BpfCoordinatorShim getBpfCoordinatorShim(@NonNull final Dependencies deps) {
        if (deps.isAtLeastS()) {
            return new com.android.networkstack.tethering.apishim.api31.BpfCoordinatorShimImpl(
                    deps);
        } else {
            return new com.android.networkstack.tethering.apishim.api30.BpfCoordinatorShimImpl(
                    deps);
        }
    }

    /**
     * Return true if this class has been initialized, otherwise return false.
     */
    public abstract boolean isInitialized();

    /**
     * Adds a tethering offload rule to BPF map, or updates it if it already exists.
     *
     * Currently, only downstream /128 IPv6 entries are supported. An existing rule will be updated
     * if the input interface and destination prefix match. Otherwise, a new rule will be created.
     * Note that this can be only called on handler thread.
     *
     * @param rule The rule to add or update.
     */
    public abstract boolean tetherOffloadRuleAdd(@NonNull Ipv6ForwardingRule rule);

    /**
     * Deletes a tethering offload rule from the BPF map.
     *
     * Currently, only downstream /128 IPv6 entries are supported. An existing rule will be deleted
     * if the destination IP address and the source interface match. It is not an error if there is
     * no matching rule to delete.
     *
     * @param rule The rule to delete.
     */
    public abstract boolean tetherOffloadRuleRemove(@NonNull Ipv6ForwardingRule rule);

    /**
     * Return BPF tethering offload statistics.
     *
     * @return an array of TetherStatsValue's, where each entry contains the upstream interface
     *         index and its tethering statistics since tethering was first started.
     *         There will only ever be one entry for a given interface index.
     */
    @Nullable
    public abstract SparseArray<TetherStatsValue> tetherOffloadGetStats();
}

