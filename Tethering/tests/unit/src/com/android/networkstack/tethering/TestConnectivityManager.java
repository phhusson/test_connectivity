/*
 * Copyright (C) 2021 The Android Open Source Project
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

package com.android.networkstack.tethering;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.IConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.os.Handler;
import android.os.UserHandle;
import android.util.ArrayMap;

import java.util.Map;
import java.util.Objects;

/**
 * Simulates upstream switching and sending NetworkCallbacks and CONNECTIVITY_ACTION broadcasts.
 *
 * Unlike any real networking code, this class is single-threaded and entirely synchronous.
 * The effects of all method calls (including sending fake broadcasts, sending callbacks, etc.) are
 * performed immediately on the caller's thread before returning.
 *
 * TODO: this duplicates a fair amount of code from ConnectivityManager and ConnectivityService.
 * Consider using a ConnectivityService object instead, as used in ConnectivityServiceTest.
 *
 * Things to consider:
 * - ConnectivityService uses a real handler for realism, and these test use TestLooper (or even
 *   invoke callbacks directly inline) for determinism. Using a real ConnectivityService would
 *   require adding dispatchAll() calls and migrating to handlers.
 * - ConnectivityService does not provide a way to order CONNECTIVITY_ACTION before or after the
 *   NetworkCallbacks for the same network change. That ability is useful because the upstream
 *   selection code in Tethering is vulnerable to race conditions, due to its reliance on multiple
 *   separate NetworkCallbacks and BroadcastReceivers, each of which trigger different types of
 *   updates. If/when the upstream selection code is refactored to a more level-triggered model
 *   (e.g., with an idempotent function that takes into account all state every time any part of
 *   that state changes), this may become less important or unnecessary.
 */
public class TestConnectivityManager extends ConnectivityManager {
    public Map<NetworkCallback, NetworkRequestInfo> allCallbacks = new ArrayMap<>();
    public Map<NetworkCallback, NetworkRequestInfo> trackingDefault = new ArrayMap<>();
    public TestNetworkAgent defaultNetwork = null;
    public Map<NetworkCallback, NetworkRequestInfo> listening = new ArrayMap<>();
    public Map<NetworkCallback, NetworkRequestInfo> requested = new ArrayMap<>();
    public Map<NetworkCallback, Integer> legacyTypeMap = new ArrayMap<>();

    private final NetworkRequest mDefaultRequest;
    private final Context mContext;

    private int mNetworkId = 100;

    /**
     * Constructs a TestConnectivityManager.
     * @param ctx the context to use. Must be a fake or a mock because otherwise the test will
     *            attempt to send real broadcasts and resulting in permission denials.
     * @param svc an IConnectivityManager. Should be a fake or a mock.
     * @param defaultRequest the default NetworkRequest that will be used by Tethering.
     */
    public TestConnectivityManager(Context ctx, IConnectivityManager svc,
            NetworkRequest defaultRequest) {
        super(ctx, svc);
        mContext = ctx;
        mDefaultRequest = defaultRequest;
    }

    class NetworkRequestInfo {
        public final NetworkRequest request;
        public final Handler handler;
        NetworkRequestInfo(NetworkRequest r, Handler h) {
            request = r;
            handler = h;
        }
    }

    boolean hasNoCallbacks() {
        return allCallbacks.isEmpty()
                && trackingDefault.isEmpty()
                && listening.isEmpty()
                && requested.isEmpty()
                && legacyTypeMap.isEmpty();
    }

    boolean onlyHasDefaultCallbacks() {
        return (allCallbacks.size() == 1)
                && (trackingDefault.size() == 1)
                && listening.isEmpty()
                && requested.isEmpty()
                && legacyTypeMap.isEmpty();
    }

    boolean isListeningForAll() {
        final NetworkCapabilities empty = new NetworkCapabilities();
        empty.clearAll();

        for (NetworkRequestInfo nri : listening.values()) {
            if (nri.request.networkCapabilities.equalRequestableCapabilities(empty)) {
                return true;
            }
        }
        return false;
    }

    int getNetworkId() {
        return ++mNetworkId;
    }

    private void sendDefaultNetworkBroadcasts(TestNetworkAgent formerDefault,
            TestNetworkAgent defaultNetwork) {
        if (formerDefault != null) {
            sendConnectivityAction(formerDefault.legacyType, false /* connected */);
        }
        if (defaultNetwork != null) {
            sendConnectivityAction(defaultNetwork.legacyType, true /* connected */);
        }
    }

    private void sendDefaultNetworkCallbacks(TestNetworkAgent formerDefault,
            TestNetworkAgent defaultNetwork) {
        for (NetworkCallback cb : trackingDefault.keySet()) {
            final NetworkRequestInfo nri = trackingDefault.get(cb);
            if (defaultNetwork != null) {
                nri.handler.post(() -> cb.onAvailable(defaultNetwork.networkId));
                nri.handler.post(() -> cb.onCapabilitiesChanged(
                        defaultNetwork.networkId, defaultNetwork.networkCapabilities));
                nri.handler.post(() -> cb.onLinkPropertiesChanged(
                        defaultNetwork.networkId, defaultNetwork.linkProperties));
            } else if (formerDefault != null) {
                nri.handler.post(() -> cb.onLost(formerDefault.networkId));
            }
        }
    }

    void makeDefaultNetwork(TestNetworkAgent agent) {
        if (Objects.equals(defaultNetwork, agent)) return;

        final TestNetworkAgent formerDefault = defaultNetwork;
        defaultNetwork = agent;

        sendDefaultNetworkCallbacks(formerDefault, defaultNetwork);
        sendDefaultNetworkBroadcasts(formerDefault, defaultNetwork);
    }

    @Override
    public void requestNetwork(NetworkRequest req, NetworkCallback cb, Handler h) {
        assertFalse(allCallbacks.containsKey(cb));
        allCallbacks.put(cb, new NetworkRequestInfo(req, h));
        if (mDefaultRequest.equals(req)) {
            assertFalse(trackingDefault.containsKey(cb));
            trackingDefault.put(cb, new NetworkRequestInfo(req, h));
        } else {
            assertFalse(requested.containsKey(cb));
            requested.put(cb, new NetworkRequestInfo(req, h));
        }
    }

    @Override
    public void requestNetwork(NetworkRequest req, NetworkCallback cb) {
        fail("Should never be called.");
    }

    @Override
    public void requestNetwork(NetworkRequest req,
            int timeoutMs, int legacyType, Handler h, NetworkCallback cb) {
        assertFalse(allCallbacks.containsKey(cb));
        allCallbacks.put(cb, new NetworkRequestInfo(req, h));
        assertFalse(requested.containsKey(cb));
        requested.put(cb, new NetworkRequestInfo(req, h));
        assertFalse(legacyTypeMap.containsKey(cb));
        if (legacyType != ConnectivityManager.TYPE_NONE) {
            legacyTypeMap.put(cb, legacyType);
        }
    }

    @Override
    public void registerNetworkCallback(NetworkRequest req, NetworkCallback cb, Handler h) {
        assertFalse(allCallbacks.containsKey(cb));
        allCallbacks.put(cb, new NetworkRequestInfo(req, h));
        assertFalse(listening.containsKey(cb));
        listening.put(cb, new NetworkRequestInfo(req, h));
    }

    @Override
    public void registerNetworkCallback(NetworkRequest req, NetworkCallback cb) {
        fail("Should never be called.");
    }

    @Override
    public void registerDefaultNetworkCallback(NetworkCallback cb, Handler h) {
        fail("Should never be called.");
    }

    @Override
    public void registerDefaultNetworkCallback(NetworkCallback cb) {
        fail("Should never be called.");
    }

    @Override
    public void unregisterNetworkCallback(NetworkCallback cb) {
        if (trackingDefault.containsKey(cb)) {
            trackingDefault.remove(cb);
        } else if (listening.containsKey(cb)) {
            listening.remove(cb);
        } else if (requested.containsKey(cb)) {
            requested.remove(cb);
            legacyTypeMap.remove(cb);
        } else {
            fail("Unexpected callback removed");
        }
        allCallbacks.remove(cb);

        assertFalse(allCallbacks.containsKey(cb));
        assertFalse(trackingDefault.containsKey(cb));
        assertFalse(listening.containsKey(cb));
        assertFalse(requested.containsKey(cb));
    }

    private void sendConnectivityAction(int type, boolean connected) {
        NetworkInfo ni = new NetworkInfo(type, 0 /* subtype */,  getNetworkTypeName(type),
                "" /* subtypeName */);
        NetworkInfo.DetailedState state = connected
                ? NetworkInfo.DetailedState.CONNECTED
                : NetworkInfo.DetailedState.DISCONNECTED;
        ni.setDetailedState(state, "" /* reason */, "" /* extraInfo */);
        Intent intent = new Intent(CONNECTIVITY_ACTION);
        intent.putExtra(EXTRA_NETWORK_INFO, ni);
        mContext.sendStickyBroadcastAsUser(intent, UserHandle.ALL);
    }

    public static class TestNetworkAgent {
        public final TestConnectivityManager cm;
        public final Network networkId;
        public final NetworkCapabilities networkCapabilities;
        public final LinkProperties linkProperties;
        // TODO: delete when tethering no longer uses CONNECTIVITY_ACTION.
        public final int legacyType;

        public TestNetworkAgent(TestConnectivityManager cm, NetworkCapabilities nc) {
            this.cm = cm;
            this.networkId = new Network(cm.getNetworkId());
            networkCapabilities = copy(nc);
            linkProperties = new LinkProperties();
            legacyType = toLegacyType(nc);
        }

        public TestNetworkAgent(TestConnectivityManager cm, UpstreamNetworkState state) {
            this.cm = cm;
            networkId = state.network;
            networkCapabilities = state.networkCapabilities;
            linkProperties = state.linkProperties;
            this.legacyType = toLegacyType(networkCapabilities);
        }

        private static int toLegacyType(NetworkCapabilities nc) {
            for (int type = 0; type < ConnectivityManager.TYPE_TEST; type++) {
                if (matchesLegacyType(nc, type)) return type;
            }
            throw new IllegalArgumentException(("Can't determine legacy type for: ") + nc);
        }

        private static boolean matchesLegacyType(NetworkCapabilities nc, int legacyType) {
            final NetworkCapabilities typeNc;
            try {
                typeNc = ConnectivityManager.networkCapabilitiesForType(legacyType);
            } catch (IllegalArgumentException e) {
                // networkCapabilitiesForType does not support all legacy types.
                return false;
            }
            return typeNc.satisfiedByNetworkCapabilities(nc);
        }

        private boolean matchesLegacyType(int legacyType) {
            return matchesLegacyType(networkCapabilities, legacyType);
        }

        public void fakeConnect() {
            for (NetworkRequestInfo nri : cm.requested.values()) {
                if (matchesLegacyType(nri.request.legacyType)) {
                    cm.sendConnectivityAction(legacyType, true /* connected */);
                    // In practice, a given network can match only one legacy type.
                    break;
                }
            }
            for (NetworkCallback cb : cm.listening.keySet()) {
                final NetworkRequestInfo nri = cm.listening.get(cb);
                nri.handler.post(() -> cb.onAvailable(networkId));
                nri.handler.post(() -> cb.onCapabilitiesChanged(
                        networkId, copy(networkCapabilities)));
                nri.handler.post(() -> cb.onLinkPropertiesChanged(networkId, copy(linkProperties)));
            }
        }

        public void fakeDisconnect() {
            for (NetworkRequestInfo nri : cm.requested.values()) {
                if (matchesLegacyType(nri.request.legacyType)) {
                    cm.sendConnectivityAction(legacyType, false /* connected */);
                    break;
                }
            }
            for (NetworkCallback cb : cm.listening.keySet()) {
                cb.onLost(networkId);
            }
        }

        public void sendLinkProperties() {
            for (NetworkCallback cb : cm.listening.keySet()) {
                cb.onLinkPropertiesChanged(networkId, copy(linkProperties));
            }
        }

        @Override
        public String toString() {
            return String.format("TestNetworkAgent: %s %s", networkId, networkCapabilities);
        }
    }

    static NetworkCapabilities copy(NetworkCapabilities nc) {
        return new NetworkCapabilities(nc);
    }

    static LinkProperties copy(LinkProperties lp) {
        return new LinkProperties(lp);
    }
}
