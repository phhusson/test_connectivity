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

package com.android.networkstack.tethering.apishim.api31;

import android.net.util.SharedLog;
import android.system.ErrnoException;
import android.system.OsConstants;
import android.util.SparseArray;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.networkstack.tethering.BpfCoordinator.Dependencies;
import com.android.networkstack.tethering.BpfCoordinator.Ipv6ForwardingRule;
import com.android.networkstack.tethering.BpfMap;
import com.android.networkstack.tethering.TetherIngressKey;
import com.android.networkstack.tethering.TetherIngressValue;
import com.android.networkstack.tethering.TetherStatsKey;
import com.android.networkstack.tethering.TetherStatsValue;

/**
 * Bpf coordinator class for API shims.
 */
public class BpfCoordinatorShimImpl
        extends com.android.networkstack.tethering.apishim.common.BpfCoordinatorShim {
    private static final String TAG = "api31.BpfCoordinatorShimImpl";

    @NonNull
    private final SharedLog mLog;

    // BPF map of ingress queueing discipline which pre-processes the packets by the IPv6
    // forwarding rules.
    @Nullable
    private final BpfMap<TetherIngressKey, TetherIngressValue> mBpfIngressMap;

    // BPF map of tethering statistics of the upstream interface since tethering startup.
    @Nullable
    private final BpfMap<TetherStatsKey, TetherStatsValue> mBpfStatsMap;

    public BpfCoordinatorShimImpl(@NonNull final Dependencies deps) {
        mLog = deps.getSharedLog().forSubComponent(TAG);
        mBpfIngressMap = deps.getBpfIngressMap();
        mBpfStatsMap = deps.getBpfStatsMap();
    }

    @Override
    public boolean isInitialized() {
        return mBpfIngressMap != null && mBpfStatsMap != null;
    }

    @Override
    public boolean tetherOffloadRuleAdd(@NonNull final Ipv6ForwardingRule rule) {
        if (!isInitialized()) return false;

        final TetherIngressKey key = rule.makeTetherIngressKey();
        final TetherIngressValue value = rule.makeTetherIngressValue();

        try {
            mBpfIngressMap.updateEntry(key, value);
        } catch (ErrnoException e) {
            mLog.e("Could not update entry: ", e);
            return false;
        }

        return true;
    }

    @Override
    public boolean tetherOffloadRuleRemove(@NonNull final Ipv6ForwardingRule rule) {
        if (!isInitialized()) return false;

        try {
            mBpfIngressMap.deleteEntry(rule.makeTetherIngressKey());
        } catch (ErrnoException e) {
            // Silent if the rule did not exist.
            if (e.errno != OsConstants.ENOENT) {
                mLog.e("Could not update entry: ", e);
                return false;
            }
        }
        return true;
    }

    @Override
    @Nullable
    public SparseArray<TetherStatsValue> tetherOffloadGetStats() {
        if (!isInitialized()) return null;

        final SparseArray<TetherStatsValue> tetherStatsList = new SparseArray<TetherStatsValue>();
        try {
            // The reported tether stats are total data usage for all currently-active upstream
            // interfaces since tethering start.
            mBpfStatsMap.forEach((key, value) -> tetherStatsList.put((int) key.ifindex, value));
        } catch (ErrnoException e) {
            mLog.e("Fail to fetch tethering stats from BPF map: ", e);
            return null;
        }
        return tetherStatsList;
    }

    @Override
    public String toString() {
        return "mBpfIngressMap{"
                + (mBpfIngressMap != null ? "initialized" : "not initialized") + "}, "
                + "mBpfStatsMap{"
                + (mBpfStatsMap != null ? "initialized" : "not initialized") + "} "
                + "}";
    }
}
