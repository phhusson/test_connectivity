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

import static android.net.netstats.provider.NetworkStatsProvider.QUOTA_UNLIMITED;

import android.net.util.SharedLog;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.SparseArray;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.networkstack.tethering.BpfCoordinator.Dependencies;
import com.android.networkstack.tethering.BpfCoordinator.Ipv6ForwardingRule;
import com.android.networkstack.tethering.BpfMap;
import com.android.networkstack.tethering.TetherDownstream6Key;
import com.android.networkstack.tethering.TetherDownstream6Value;
import com.android.networkstack.tethering.TetherLimitKey;
import com.android.networkstack.tethering.TetherLimitValue;
import com.android.networkstack.tethering.TetherStatsKey;
import com.android.networkstack.tethering.TetherStatsValue;

import java.io.FileDescriptor;

/**
 * Bpf coordinator class for API shims.
 */
public class BpfCoordinatorShimImpl
        extends com.android.networkstack.tethering.apishim.common.BpfCoordinatorShim {
    private static final String TAG = "api31.BpfCoordinatorShimImpl";

    // AF_KEY socket type. See include/linux/socket.h.
    private static final int AF_KEY = 15;
    // PFKEYv2 constants. See include/uapi/linux/pfkeyv2.h.
    private static final int PF_KEY_V2 = 2;

    @NonNull
    private final SharedLog mLog;

    // BPF map of ingress queueing discipline which pre-processes the packets by the IPv6
    // forwarding rules.
    @Nullable
    private final BpfMap<TetherDownstream6Key, TetherDownstream6Value> mBpfDownstream6Map;

    // BPF map of tethering statistics of the upstream interface since tethering startup.
    @Nullable
    private final BpfMap<TetherStatsKey, TetherStatsValue> mBpfStatsMap;

    // BPF map of per-interface quota for tethering offload.
    @Nullable
    private final BpfMap<TetherLimitKey, TetherLimitValue> mBpfLimitMap;

    public BpfCoordinatorShimImpl(@NonNull final Dependencies deps) {
        mLog = deps.getSharedLog().forSubComponent(TAG);
        mBpfDownstream6Map = deps.getBpfDownstream6Map();
        mBpfStatsMap = deps.getBpfStatsMap();
        mBpfLimitMap = deps.getBpfLimitMap();
    }

    @Override
    public boolean isInitialized() {
        return mBpfDownstream6Map != null && mBpfStatsMap != null  && mBpfLimitMap != null;
    }

    @Override
    public boolean tetherOffloadRuleAdd(@NonNull final Ipv6ForwardingRule rule) {
        if (!isInitialized()) return false;

        final TetherDownstream6Key key = rule.makeTetherDownstream6Key();
        final TetherDownstream6Value value = rule.makeTetherDownstream6Value();

        try {
            mBpfDownstream6Map.updateEntry(key, value);
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
            mBpfDownstream6Map.deleteEntry(rule.makeTetherDownstream6Key());
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
    public boolean tetherOffloadSetInterfaceQuota(int ifIndex, long quotaBytes) {
        if (!isInitialized()) return false;

        // The common case is an update, where the stats already exist,
        // hence we read first, even though writing with BPF_NOEXIST
        // first would make the code simpler.
        long rxBytes, txBytes;
        TetherStatsValue statsValue = null;

        try {
            statsValue = mBpfStatsMap.getValue(new TetherStatsKey(ifIndex));
        } catch (ErrnoException e) {
            // The BpfMap#getValue doesn't throw an errno ENOENT exception. Catch other error
            // while trying to get stats entry.
            mLog.e("Could not get stats entry of interface index " + ifIndex + ": ", e);
            return false;
        }

        if (statsValue != null) {
            // Ok, there was a stats entry.
            rxBytes = statsValue.rxBytes;
            txBytes = statsValue.txBytes;
        } else {
            // No stats entry - create one with zeroes.
            try {
                // This function is the *only* thing that can create entries.
                // BpfMap#insertEntry use BPF_NOEXIST to create the entry. The entry is created
                // if and only if it doesn't exist.
                mBpfStatsMap.insertEntry(new TetherStatsKey(ifIndex), new TetherStatsValue(
                        0 /* rxPackets */, 0 /* rxBytes */, 0 /* rxErrors */, 0 /* txPackets */,
                        0 /* txBytes */, 0 /* txErrors */));
            } catch (ErrnoException | IllegalArgumentException e) {
                mLog.e("Could not create stats entry: ", e);
                return false;
            }
            rxBytes = 0;
            txBytes = 0;
        }

        // rxBytes + txBytes won't overflow even at 5gbps for ~936 years.
        long newLimit = rxBytes + txBytes + quotaBytes;

        // if adding limit (e.g., if limit is QUOTA_UNLIMITED) caused overflow: clamp to 'infinity'
        if (newLimit < rxBytes + txBytes) newLimit = QUOTA_UNLIMITED;

        try {
            mBpfLimitMap.updateEntry(new TetherLimitKey(ifIndex), new TetherLimitValue(newLimit));
        } catch (ErrnoException e) {
            mLog.e("Fail to set quota " + quotaBytes + " for interface index " + ifIndex + ": ", e);
            return false;
        }

        return true;
    }

    @Override
    @Nullable
    public TetherStatsValue tetherOffloadGetAndClearStats(int ifIndex) {
        if (!isInitialized()) return null;

        // getAndClearTetherOffloadStats is called after all offload rules have already been
        // deleted for the given upstream interface. Before starting to do cleanup stuff in this
        // function, use synchronizeKernelRCU to make sure that all the current running eBPF
        // programs are finished on all CPUs, especially the unfinished packet processing. After
        // synchronizeKernelRCU returned, we can safely read or delete on the stats map or the
        // limit map.
        final int res = synchronizeKernelRCU();
        if (res != 0) {
            // Error log but don't return. Do as much cleanup as possible.
            mLog.e("synchronize_rcu() failed: " + res);
        }

        TetherStatsValue statsValue = null;
        try {
            statsValue = mBpfStatsMap.getValue(new TetherStatsKey(ifIndex));
        } catch (ErrnoException e) {
            mLog.e("Could not get stats entry for interface index " + ifIndex + ": ", e);
            return null;
        }

        if (statsValue == null) {
            mLog.e("Could not get stats entry for interface index " + ifIndex);
            return null;
        }

        try {
            mBpfStatsMap.deleteEntry(new TetherStatsKey(ifIndex));
        } catch (ErrnoException e) {
            mLog.e("Could not delete stats entry for interface index " + ifIndex + ": ", e);
            return null;
        }

        try {
            mBpfLimitMap.deleteEntry(new TetherLimitKey(ifIndex));
        } catch (ErrnoException e) {
            mLog.e("Could not delete limit for interface index " + ifIndex + ": ", e);
            return null;
        }

        return statsValue;
    }

    @Override
    public String toString() {
        return "mBpfDownstream6Map{"
                + (mBpfDownstream6Map != null ? "initialized" : "not initialized") + "}, "
                + "mBpfStatsMap{"
                + (mBpfStatsMap != null ? "initialized" : "not initialized") + "}, "
                + "mBpfLimitMap{"
                + (mBpfLimitMap != null ? "initialized" : "not initialized") + "} "
                + "}";
    }

    /**
     * Call synchronize_rcu() to block until all existing RCU read-side critical sections have
     * been completed.
     * Note that BpfCoordinatorTest have no permissions to create or close pf_key socket. It is
     * okay for now because the caller #bpfGetAndClearStats doesn't care the result of this
     * function. The tests don't be broken.
     * TODO: Wrap this function into Dependencies for mocking in tests.
     */
    private int synchronizeKernelRCU() {
        // This is a temporary hack for network stats map swap on devices running
        // 4.9 kernels. The kernel code of socket release on pf_key socket will
        // explicitly call synchronize_rcu() which is exactly what we need.
        FileDescriptor pfSocket;
        try {
            pfSocket = Os.socket(AF_KEY, OsConstants.SOCK_RAW | OsConstants.SOCK_CLOEXEC,
                    PF_KEY_V2);
        } catch (ErrnoException e) {
            mLog.e("create PF_KEY socket failed: ", e);
            return e.errno;
        }

        // When closing socket, synchronize_rcu() gets called in sock_release().
        try {
            Os.close(pfSocket);
        } catch (ErrnoException e) {
            mLog.e("failed to close the PF_KEY socket: ", e);
            return e.errno;
        }

        return 0;
    }
}
