/*
 * Copyright (C) 2019 The Android Open Source Project
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

package android.net.cts.api23test;

import static android.content.pm.PackageManager.FEATURE_WIFI;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkInfo.State;
import android.net.NetworkRequest;
import android.net.wifi.WifiManager;
import android.os.Looper;
import android.system.Os;
import android.system.OsConstants;
import android.test.AndroidTestCase;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class ConnectivityManagerApi23Test extends AndroidTestCase {
    private static final String TAG = ConnectivityManagerApi23Test.class.getSimpleName();

    private static final String TEST_HOST = "connectivitycheck.gstatic.com";
    private static final int SOCKET_TIMEOUT_MS = 2000;
    private static final int SEND_BROADCAST_TIMEOUT = 30000;
    private static final int HTTP_PORT = 80;
    // Intent string to get the number of wifi CONNECTIVITY_ACTION callbacks the test app has seen
    public static final String GET_WIFI_CONNECTIVITY_ACTION_COUNT =
            "android.net.cts.appForApi23.getWifiConnectivityActionCount";
    // Action sent to ConnectivityActionReceiver when a network callback is sent via PendingIntent.
    private static final String NETWORK_CALLBACK_ACTION =
            "ConnectivityManagerTest.NetworkCallbackAction";
    private static final String HTTP_REQUEST =
            "GET /generate_204 HTTP/1.0\r\n" +
                    "Host: " + TEST_HOST + "\r\n" +
                    "Connection: keep-alive\r\n\r\n";

    private Context mContext;
    private ConnectivityManager mCm;
    private WifiManager mWifiManager;
    private PackageManager mPackageManager;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        Looper.prepare();
        mContext = getContext();
        mCm = (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        mWifiManager = (WifiManager) mContext.getSystemService(Context.WIFI_SERVICE);
        mPackageManager = mContext.getPackageManager();
    }

    /**
     * Tests reporting of connectivity changed.
     */
    public void testConnectivityChanged_manifestRequestOnly_shouldNotReceiveIntent() {
        if (!mPackageManager.hasSystemFeature(FEATURE_WIFI)) {
            Log.i(TAG, "testConnectivityChanged_manifestRequestOnly_shouldNotReceiveIntent cannot execute unless device supports WiFi");
            return;
        }
        ConnectivityReceiver.prepare();

        toggleWifi();

        // The connectivity broadcast has been sent; push through a terminal broadcast
        // to wait for in the receive to confirm it didn't see the connectivity change.
        Intent finalIntent = new Intent(ConnectivityReceiver.FINAL_ACTION);
        finalIntent.setClass(mContext, ConnectivityReceiver.class);
        mContext.sendBroadcast(finalIntent);
        assertFalse(ConnectivityReceiver.waitForBroadcast());
    }

    public void testConnectivityChanged_manifestRequestOnlyPreN_shouldReceiveIntent()
            throws InterruptedException {
        if (!mPackageManager.hasSystemFeature(FEATURE_WIFI)) {
            Log.i(TAG, "testConnectivityChanged_manifestRequestOnlyPreN_shouldReceiveIntent cannot"
                    + "execute unless device supports WiFi");
            return;
        }
        mContext.startActivity(new Intent()
                .setComponent(new ComponentName("android.net.cts.appForApi23",
                        "android.net.cts.appForApi23.ConnectivityListeningActivity"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
        Thread.sleep(200);

        toggleWifi();

        Intent getConnectivityCount = new Intent(GET_WIFI_CONNECTIVITY_ACTION_COUNT);
        assertEquals(2, sendOrderedBroadcastAndReturnResultCode(
                getConnectivityCount, SEND_BROADCAST_TIMEOUT));
    }

    public void testConnectivityChanged_whenRegistered_shouldReceiveIntent() {
        if (!mPackageManager.hasSystemFeature(FEATURE_WIFI)) {
            Log.i(TAG, "testConnectivityChanged_whenRegistered_shouldReceiveIntent cannot execute unless device supports WiFi");
            return;
        }
        ConnectivityReceiver.prepare();
        ConnectivityReceiver receiver = new ConnectivityReceiver();
        IntentFilter filter = new IntentFilter();
        filter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        mContext.registerReceiver(receiver, filter);

        toggleWifi();
        Intent finalIntent = new Intent(ConnectivityReceiver.FINAL_ACTION);
        finalIntent.setClass(mContext, ConnectivityReceiver.class);
        mContext.sendBroadcast(finalIntent);

        assertTrue(ConnectivityReceiver.waitForBroadcast());
    }

    // Toggle WiFi twice, leaving it in the state it started in
    private void toggleWifi() {
        if (mWifiManager.isWifiEnabled()) {
            Network wifiNetwork = getWifiNetwork();
            disconnectFromWifi(wifiNetwork);
            connectToWifi();
        } else {
            connectToWifi();
            Network wifiNetwork = getWifiNetwork();
            disconnectFromWifi(wifiNetwork);
        }
    }

    private int sendOrderedBroadcastAndReturnResultCode(
            Intent intent, int timeoutMs) throws InterruptedException {
        final LinkedBlockingQueue<Integer> result = new LinkedBlockingQueue<>(1);
        mContext.sendOrderedBroadcast(intent, null, new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                result.offer(getResultCode());
            }
        }, null, 0, null, null);

        Integer resultCode = result.poll(timeoutMs, TimeUnit.MILLISECONDS);
        assertNotNull("Timed out (more than " + timeoutMs +
                " milliseconds) waiting for result code for broadcast", resultCode);
        return resultCode;
    }

    private Network getWifiNetwork() {
        TestNetworkCallback callback = new TestNetworkCallback();
        mCm.registerNetworkCallback(makeWifiNetworkRequest(), callback);
        Network network = null;
        try {
            network = callback.waitForAvailable();
        } catch (InterruptedException e) {
            fail("NetworkCallback wait was interrupted.");
        } finally {
            mCm.unregisterNetworkCallback(callback);
        }
        assertNotNull("Cannot find Network for wifi. Is wifi connected?", network);
        return network;
    }

    /** Disable WiFi and wait for it to become disconnected from the network. */
    private void disconnectFromWifi(Network wifiNetworkToCheck) {
        final TestNetworkCallback callback = new TestNetworkCallback();
        mCm.registerNetworkCallback(makeWifiNetworkRequest(), callback);
        Network lostWifiNetwork = null;

        ConnectivityActionReceiver receiver = new ConnectivityActionReceiver(
                ConnectivityManager.TYPE_WIFI, NetworkInfo.State.DISCONNECTED);
        IntentFilter filter = new IntentFilter();
        filter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        mContext.registerReceiver(receiver, filter);

        // Assert that we can establish a TCP connection on wifi.
        Socket wifiBoundSocket = null;
        if (wifiNetworkToCheck != null) {
            try {
                wifiBoundSocket = getBoundSocket(wifiNetworkToCheck, TEST_HOST, HTTP_PORT);
                testHttpRequest(wifiBoundSocket);
            } catch (IOException e) {
                fail("HTTP request before wifi disconnected failed with: " + e);
            }
        }

        boolean disconnected = false;
        try {
            assertTrue(mWifiManager.setWifiEnabled(false));
            // Ensure we get both an onLost callback and a CONNECTIVITY_ACTION.
            lostWifiNetwork = callback.waitForLost();
            assertNotNull(lostWifiNetwork);
            disconnected = receiver.waitForState();
        } catch (InterruptedException ex) {
            fail("disconnectFromWifi was interrupted");
        } finally {
            mCm.unregisterNetworkCallback(callback);
            mContext.unregisterReceiver(receiver);
        }

        assertTrue("Wifi failed to reach DISCONNECTED state.", disconnected);

        // Check that the socket is closed when wifi disconnects.
        if (wifiBoundSocket != null) {
            try {
                testHttpRequest(wifiBoundSocket);
                fail("HTTP request should not succeed after wifi disconnects");
            } catch (IOException expected) {
                assertEquals(Os.strerror(OsConstants.ECONNABORTED), expected.getMessage());
            }
        }
    }

    /** Enable WiFi and wait for it to become connected to a network. */
    private Network connectToWifi() {
        final TestNetworkCallback callback = new TestNetworkCallback();
        mCm.registerNetworkCallback(makeWifiNetworkRequest(), callback);
        Network wifiNetwork = null;

        ConnectivityActionReceiver receiver = new ConnectivityActionReceiver(
                ConnectivityManager.TYPE_WIFI, NetworkInfo.State.CONNECTED);
        IntentFilter filter = new IntentFilter();
        filter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        mContext.registerReceiver(receiver, filter);

        boolean connected = false;
        try {
            assertTrue(mWifiManager.setWifiEnabled(true));
            // Ensure we get both an onAvailable callback and a CONNECTIVITY_ACTION.
            wifiNetwork = callback.waitForAvailable();
            assertNotNull(wifiNetwork);
            connected = receiver.waitForState();
        } catch (InterruptedException ex) {
            fail("connectToWifi was interrupted");
        } finally {
            mCm.unregisterNetworkCallback(callback);
            mContext.unregisterReceiver(receiver);
        }

        assertTrue("Wifi must be configured to connect to an access point for this test.",
                connected);
        return wifiNetwork;
    }

    private NetworkRequest makeWifiNetworkRequest() {
        return new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .build();
    }

    private void testHttpRequest(Socket s) throws IOException {
        OutputStream out = s.getOutputStream();
        InputStream in = s.getInputStream();

        final byte[] requestBytes = HTTP_REQUEST.getBytes("UTF-8");
        byte[] responseBytes = new byte[4096];
        out.write(requestBytes);
        in.read(responseBytes);
        assertTrue(new String(responseBytes, "UTF-8").startsWith("HTTP/1.0 204 No Content\r\n"));
    }

    private Socket getBoundSocket(Network network, String host, int port) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(host, port);
        Socket s = network.getSocketFactory().createSocket();
        try {
            s.setSoTimeout(SOCKET_TIMEOUT_MS);
            s.connect(addr, SOCKET_TIMEOUT_MS);
        } catch (IOException e) {
            s.close();
            throw e;
        }
        return s;
    }

    /**
     * Receiver that captures the last connectivity change's network type and state. Recognizes
     * both {@code CONNECTIVITY_ACTION} and {@code NETWORK_CALLBACK_ACTION} intents.
     */
    private class ConnectivityActionReceiver extends BroadcastReceiver {

        private final CountDownLatch mReceiveLatch = new CountDownLatch(1);

        private final int mNetworkType;
        private final NetworkInfo.State mNetState;

        ConnectivityActionReceiver(int networkType, NetworkInfo.State netState) {
            mNetworkType = networkType;
            mNetState = netState;
        }

        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            NetworkInfo networkInfo = null;

            // When receiving ConnectivityManager.CONNECTIVITY_ACTION, the NetworkInfo parcelable
            // is stored in EXTRA_NETWORK_INFO. With a NETWORK_CALLBACK_ACTION, the Network is
            // sent in EXTRA_NETWORK and we need to ask the ConnectivityManager for the NetworkInfo.
            if (ConnectivityManager.CONNECTIVITY_ACTION.equals(action)) {
                networkInfo = intent.getExtras()
                        .getParcelable(ConnectivityManager.EXTRA_NETWORK_INFO);
                assertNotNull("ConnectivityActionReceiver expected EXTRA_NETWORK_INFO", networkInfo);
            } else if (NETWORK_CALLBACK_ACTION.equals(action)) {
                Network network = intent.getExtras()
                        .getParcelable(ConnectivityManager.EXTRA_NETWORK);
                assertNotNull("ConnectivityActionReceiver expected EXTRA_NETWORK", network);
                networkInfo = mCm.getNetworkInfo(network);
                if (networkInfo == null) {
                    // When disconnecting, it seems like we get an intent sent with an invalid
                    // Network; that is, by the time we call ConnectivityManager.getNetworkInfo(),
                    // it is invalid. Ignore these.
                    Log.i(TAG, "ConnectivityActionReceiver NETWORK_CALLBACK_ACTION ignoring "
                            + "invalid network");
                    return;
                }
            } else {
                fail("ConnectivityActionReceiver received unxpected intent action: " + action);
            }

            assertNotNull("ConnectivityActionReceiver didn't find NetworkInfo", networkInfo);
            int networkType = networkInfo.getType();
            State networkState = networkInfo.getState();
            Log.i(TAG, "Network type: " + networkType + " state: " + networkState);
            if (networkType == mNetworkType && networkInfo.getState() == mNetState) {
                mReceiveLatch.countDown();
            }
        }

        public boolean waitForState() throws InterruptedException {
            return mReceiveLatch.await(30, TimeUnit.SECONDS);
        }
    }

    /**
     * Callback used in testRegisterNetworkCallback that allows caller to block on
     * {@code onAvailable}.
     */
    private static class TestNetworkCallback extends ConnectivityManager.NetworkCallback {
        private final CountDownLatch mAvailableLatch = new CountDownLatch(1);
        private final CountDownLatch mLostLatch = new CountDownLatch(1);
        private final CountDownLatch mUnavailableLatch = new CountDownLatch(1);

        public Network currentNetwork;
        public Network lastLostNetwork;

        public Network waitForAvailable() throws InterruptedException {
            return mAvailableLatch.await(30, TimeUnit.SECONDS) ? currentNetwork : null;
        }

        public Network waitForLost() throws InterruptedException {
            return mLostLatch.await(30, TimeUnit.SECONDS) ? lastLostNetwork : null;
        }

        public boolean waitForUnavailable() throws InterruptedException {
            return mUnavailableLatch.await(2, TimeUnit.SECONDS);
        }


        @Override
        public void onAvailable(Network network) {
            currentNetwork = network;
            mAvailableLatch.countDown();
        }

        @Override
        public void onLost(Network network) {
            lastLostNetwork = network;
            if (network.equals(currentNetwork)) {
                currentNetwork = null;
            }
            mLostLatch.countDown();
        }

        @Override
        public void onUnavailable() {
            mUnavailableLatch.countDown();
        }
    }
}