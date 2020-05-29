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

package android.net.cts;

import static android.net.ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback;
import static android.net.ConnectivityDiagnosticsManager.ConnectivityReport;
import static android.net.ConnectivityDiagnosticsManager.ConnectivityReport.KEY_NETWORK_PROBES_ATTEMPTED_BITMASK;
import static android.net.ConnectivityDiagnosticsManager.ConnectivityReport.KEY_NETWORK_PROBES_SUCCEEDED_BITMASK;
import static android.net.ConnectivityDiagnosticsManager.ConnectivityReport.KEY_NETWORK_VALIDATION_RESULT;
import static android.net.ConnectivityDiagnosticsManager.ConnectivityReport.NETWORK_VALIDATION_RESULT_VALID;
import static android.net.ConnectivityDiagnosticsManager.DataStallReport;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
import static android.net.NetworkCapabilities.TRANSPORT_TEST;
import static android.net.cts.util.CtsNetUtils.TestNetworkCallback;

import static com.android.compatibility.common.util.SystemUtil.runWithShellPermissionIdentity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.annotation.NonNull;
import android.content.Context;
import android.net.ConnectivityDiagnosticsManager;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.TestNetworkInterface;
import android.net.TestNetworkManager;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.PersistableBundle;
import android.os.Process;
import android.util.Pair;

import androidx.test.InstrumentationRegistry;

import com.android.testutils.ArrayTrackRecord;
import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo;
import com.android.testutils.DevSdkIgnoreRunner;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.Executor;

@RunWith(DevSdkIgnoreRunner.class)
@IgnoreUpTo(Build.VERSION_CODES.Q) // ConnectivityDiagnosticsManager did not exist in Q
public class ConnectivityDiagnosticsManagerTest {
    private static final int CALLBACK_TIMEOUT_MILLIS = 5000;
    private static final int NO_CALLBACK_INVOKED_TIMEOUT = 500;

    private static final Executor INLINE_EXECUTOR = x -> x.run();

    private static final NetworkRequest TEST_NETWORK_REQUEST =
            new NetworkRequest.Builder()
                    .addTransportType(TRANSPORT_TEST)
                    .removeCapability(NET_CAPABILITY_TRUSTED)
                    .removeCapability(NET_CAPABILITY_NOT_VPN)
                    .build();

    // Callback used to keep TestNetworks up when there are no other outstanding NetworkRequests
    // for it.
    private static final TestNetworkCallback TEST_NETWORK_CALLBACK = new TestNetworkCallback();

    private static final IBinder BINDER = new Binder();

    private Context mContext;
    private ConnectivityManager mConnectivityManager;
    private ConnectivityDiagnosticsManager mCdm;
    private Network mTestNetwork;

    @Before
    public void setUp() throws Exception {
        mContext = InstrumentationRegistry.getContext();
        mConnectivityManager = mContext.getSystemService(ConnectivityManager.class);
        mCdm = mContext.getSystemService(ConnectivityDiagnosticsManager.class);

        mConnectivityManager.requestNetwork(TEST_NETWORK_REQUEST, TEST_NETWORK_CALLBACK);
    }

    @After
    public void tearDown() throws Exception {
        mConnectivityManager.unregisterNetworkCallback(TEST_NETWORK_CALLBACK);

        if (mTestNetwork != null) {
            runWithShellPermissionIdentity(() -> {
                final TestNetworkManager tnm = mContext.getSystemService(TestNetworkManager.class);
                tnm.teardownTestNetwork(mTestNetwork);
            });
        }
    }

    @Test
    public void testRegisterConnectivityDiagnosticsCallback() throws Exception {
        mTestNetwork = setUpTestNetwork();

        final TestConnectivityDiagnosticsCallback cb = new TestConnectivityDiagnosticsCallback();
        mCdm.registerConnectivityDiagnosticsCallback(TEST_NETWORK_REQUEST, INLINE_EXECUTOR, cb);

        final String interfaceName =
                mConnectivityManager.getLinkProperties(mTestNetwork).getInterfaceName();

        cb.expectOnConnectivityReportAvailable(mTestNetwork, interfaceName);
        cb.assertNoCallback();
    }

    @Test
    public void testRegisterDuplicateConnectivityDiagnosticsCallback() {
        final TestConnectivityDiagnosticsCallback cb = new TestConnectivityDiagnosticsCallback();
        mCdm.registerConnectivityDiagnosticsCallback(TEST_NETWORK_REQUEST, INLINE_EXECUTOR, cb);

        try {
            mCdm.registerConnectivityDiagnosticsCallback(TEST_NETWORK_REQUEST, INLINE_EXECUTOR, cb);
            fail("Registering the same callback twice should throw an IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testUnregisterConnectivityDiagnosticsCallback() {
        final TestConnectivityDiagnosticsCallback cb = new TestConnectivityDiagnosticsCallback();
        mCdm.registerConnectivityDiagnosticsCallback(TEST_NETWORK_REQUEST, INLINE_EXECUTOR, cb);
        mCdm.unregisterConnectivityDiagnosticsCallback(cb);
    }

    @Test
    public void testUnregisterUnknownConnectivityDiagnosticsCallback() {
        // Expected to silently ignore the unregister() call
        mCdm.unregisterConnectivityDiagnosticsCallback(new TestConnectivityDiagnosticsCallback());
    }

    @Test
    public void testOnConnectivityReportAvailable() throws Exception {
        mTestNetwork = setUpTestNetwork();

        final TestConnectivityDiagnosticsCallback cb = new TestConnectivityDiagnosticsCallback();
        mCdm.registerConnectivityDiagnosticsCallback(TEST_NETWORK_REQUEST, INLINE_EXECUTOR, cb);

        final String interfaceName =
                mConnectivityManager.getLinkProperties(mTestNetwork).getInterfaceName();

        cb.expectOnConnectivityReportAvailable(mTestNetwork, interfaceName);
        cb.assertNoCallback();
    }

    @Test
    public void testOnNetworkConnectivityReportedTrue() throws Exception {
        verifyOnNetworkConnectivityReported(true /* hasConnectivity */);
    }

    @Test
    public void testOnNetworkConnectivityReportedFalse() throws Exception {
        verifyOnNetworkConnectivityReported(false /* hasConnectivity */);
    }

    private void verifyOnNetworkConnectivityReported(boolean hasConnectivity) throws Exception {
        mTestNetwork = setUpTestNetwork();

        final TestConnectivityDiagnosticsCallback cb = new TestConnectivityDiagnosticsCallback();
        mCdm.registerConnectivityDiagnosticsCallback(TEST_NETWORK_REQUEST, INLINE_EXECUTOR, cb);

        // onConnectivityReportAvailable always invoked when the test network is established
        final String interfaceName =
                mConnectivityManager.getLinkProperties(mTestNetwork).getInterfaceName();
        cb.expectOnConnectivityReportAvailable(mTestNetwork, interfaceName);
        cb.assertNoCallback();

        mConnectivityManager.reportNetworkConnectivity(mTestNetwork, hasConnectivity);

        cb.expectOnNetworkConnectivityReported(mTestNetwork, hasConnectivity);

        // if hasConnectivity does not match the network's known connectivity, it will be
        // revalidated which will trigger another onConnectivityReportAvailable callback.
        if (!hasConnectivity) {
            cb.expectOnConnectivityReportAvailable(mTestNetwork, interfaceName);
        }

        cb.assertNoCallback();
    }

    @NonNull
    private Network waitForConnectivityServiceIdleAndGetNetwork() throws InterruptedException {
        // Get a new Network. This requires going through the ConnectivityService thread. Once it
        // completes, all previously enqueued messages on the ConnectivityService main Handler have
        // completed.
        final TestNetworkCallback callback = new TestNetworkCallback();
        mConnectivityManager.requestNetwork(TEST_NETWORK_REQUEST, callback);
        final Network network = callback.waitForAvailable();
        mConnectivityManager.unregisterNetworkCallback(callback);
        assertNotNull(network);
        return network;
    }

    /**
     * Registers a test NetworkAgent with ConnectivityService with limited capabilities, which leads
     * to the Network being validated.
     */
    @NonNull
    private Network setUpTestNetwork() throws Exception {
        final int[] administratorUids = new int[] {Process.myUid()};
        runWithShellPermissionIdentity(
                () -> {
                    final TestNetworkManager tnm =
                            mContext.getSystemService(TestNetworkManager.class);
                    final TestNetworkInterface tni = tnm.createTunInterface(new LinkAddress[0]);
                    tnm.setupTestNetwork(tni.getInterfaceName(), administratorUids, BINDER);
                });
        return waitForConnectivityServiceIdleAndGetNetwork();
    }

    private static class TestConnectivityDiagnosticsCallback
            extends ConnectivityDiagnosticsCallback {
        private final ArrayTrackRecord<Object>.ReadHead mHistory =
                new ArrayTrackRecord<Object>().newReadHead();

        @Override
        public void onConnectivityReportAvailable(ConnectivityReport report) {
            mHistory.add(report);
        }

        @Override
        public void onDataStallSuspected(DataStallReport report) {
            mHistory.add(report);
        }

        @Override
        public void onNetworkConnectivityReported(Network network, boolean hasConnectivity) {
            mHistory.add(new Pair<Network, Boolean>(network, hasConnectivity));
        }

        public void expectOnConnectivityReportAvailable(
                @NonNull Network network, @NonNull String interfaceName) {
            final ConnectivityReport result =
                    (ConnectivityReport) mHistory.poll(CALLBACK_TIMEOUT_MILLIS, x -> true);
            assertEquals(network, result.getNetwork());

            final NetworkCapabilities nc = result.getNetworkCapabilities();
            assertNotNull(nc);
            assertTrue(nc.hasTransport(TRANSPORT_TEST));
            assertNotNull(result.getLinkProperties());
            assertEquals(interfaceName, result.getLinkProperties().getInterfaceName());

            final PersistableBundle extras = result.getAdditionalInfo();
            assertTrue(extras.containsKey(KEY_NETWORK_VALIDATION_RESULT));
            final int validationResult = extras.getInt(KEY_NETWORK_VALIDATION_RESULT);
            assertEquals("Network validation result is not 'valid'",
                    NETWORK_VALIDATION_RESULT_VALID, validationResult);

            assertTrue(extras.containsKey(KEY_NETWORK_PROBES_SUCCEEDED_BITMASK));
            final int probesSucceeded = extras.getInt(KEY_NETWORK_VALIDATION_RESULT);
            assertTrue("PROBES_SUCCEEDED mask not in expected range", probesSucceeded >= 0);

            assertTrue(extras.containsKey(KEY_NETWORK_PROBES_ATTEMPTED_BITMASK));
            final int probesAttempted = extras.getInt(KEY_NETWORK_PROBES_ATTEMPTED_BITMASK);
            assertTrue("PROBES_ATTEMPTED mask not in expected range", probesAttempted >= 0);
        }

        public void expectOnNetworkConnectivityReported(
                @NonNull Network network, boolean hasConnectivity) {
            final Pair<Network, Boolean> result =
                    (Pair<Network, Boolean>) mHistory.poll(CALLBACK_TIMEOUT_MILLIS, x -> true);
            assertEquals(network, result.first /* network */);
            assertEquals(hasConnectivity, result.second /* hasConnectivity */);
        }

        public void assertNoCallback() {
            // If no more callbacks exist, there should be nothing left in the ReadHead
            assertNull("Unexpected event in history",
                    mHistory.poll(NO_CALLBACK_INVOKED_TIMEOUT, x -> true));
        }
    }
}
