/*
 * Copyright (C) 2009 The Android Open Source Project
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

import static android.content.pm.PackageManager.FEATURE_TELEPHONY;
import static android.content.pm.PackageManager.FEATURE_WIFI;
import static android.net.NetworkCapabilities.NET_CAPABILITY_IMS;
import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED;
import static android.net.NetworkCapabilities.TRANSPORT_CELLULAR;
import static android.net.NetworkCapabilities.TRANSPORT_WIFI;
import static android.os.MessageQueue.OnFileDescriptorEventListener.EVENT_INPUT;
import static android.provider.Settings.Global.NETWORK_METERED_MULTIPATH_PREFERENCE;
import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.AF_INET6;
import static android.system.OsConstants.AF_UNSPEC;

import static com.android.compatibility.common.util.SystemUtil.runShellCommand;

import android.app.Instrumentation;
import android.app.PendingIntent;
import android.app.UiAutomation;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.IpSecManager;
import android.net.IpSecManager.UdpEncapsulationSocket;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkConfig;
import android.net.NetworkInfo;
import android.net.NetworkInfo.DetailedState;
import android.net.NetworkInfo.State;
import android.net.NetworkRequest;
import android.net.SocketKeepalive;
import android.net.util.KeepaliveUtils;
import android.net.wifi.WifiManager;
import android.os.Looper;
import android.os.MessageQueue;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.VintfRuntimeInfo;
import android.platform.test.annotations.AppModeFull;
import android.provider.Settings;
import android.system.Os;
import android.system.OsConstants;
import android.test.AndroidTestCase;
import android.text.TextUtils;
import android.util.Log;
import android.util.Pair;

import androidx.test.InstrumentationRegistry;

import com.android.internal.R;
import com.android.internal.telephony.PhoneConstants;

import libcore.io.Streams;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConnectivityManagerTest extends AndroidTestCase {

    private static final String TAG = ConnectivityManagerTest.class.getSimpleName();

    public static final int TYPE_MOBILE = ConnectivityManager.TYPE_MOBILE;
    public static final int TYPE_WIFI = ConnectivityManager.TYPE_WIFI;

    private static final int HOST_ADDRESS = 0x7f000001;// represent ip 127.0.0.1
    private static final String TEST_HOST = "connectivitycheck.gstatic.com";
    private static final int SOCKET_TIMEOUT_MS = 2000;
    private static final int CONNECT_TIMEOUT_MS = 2000;
    private static final int KEEPALIVE_CALLBACK_TIMEOUT_MS = 2000;
    private static final int KEEPALIVE_SOCKET_TIMEOUT_MS = 5000;
    private static final int MIN_KEEPALIVE_INTERVAL = 10;
    private static final int NETWORK_CHANGE_METEREDNESS_TIMEOUT = 5000;
    private static final int NUM_TRIES_MULTIPATH_PREF_CHECK = 20;
    private static final long INTERVAL_MULTIPATH_PREF_CHECK_MS = 500;
    private static final int HTTP_PORT = 80;
    private static final String HTTP_REQUEST =
            "GET /generate_204 HTTP/1.0\r\n" +
            "Host: " + TEST_HOST + "\r\n" +
            "Connection: keep-alive\r\n\r\n";

    // Action sent to ConnectivityActionReceiver when a network callback is sent via PendingIntent.
    private static final String NETWORK_CALLBACK_ACTION =
            "ConnectivityManagerTest.NetworkCallbackAction";

    // device could have only one interface: data, wifi.
    private static final int MIN_NUM_NETWORK_TYPES = 1;

    private Context mContext;
    private Instrumentation mInstrumentation;
    private ConnectivityManager mCm;
    private WifiManager mWifiManager;
    private PackageManager mPackageManager;
    private final HashMap<Integer, NetworkConfig> mNetworks =
            new HashMap<Integer, NetworkConfig>();
    boolean mWifiConnectAttempted;
    private TestNetworkCallback mCellNetworkCallback;
    private UiAutomation mUiAutomation;
    private boolean mShellPermissionIdentityAdopted;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        Looper.prepare();
        mContext = getContext();
        mInstrumentation = InstrumentationRegistry.getInstrumentation();
        mCm = (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        mWifiManager = (WifiManager) mContext.getSystemService(Context.WIFI_SERVICE);
        mPackageManager = mContext.getPackageManager();
        mWifiConnectAttempted = false;

        // Get com.android.internal.R.array.networkAttributes
        int resId = mContext.getResources().getIdentifier("networkAttributes", "array", "android");
        String[] naStrings = mContext.getResources().getStringArray(resId);
        //TODO: What is the "correct" way to determine if this is a wifi only device?
        boolean wifiOnly = SystemProperties.getBoolean("ro.radio.noril", false);
        for (String naString : naStrings) {
            try {
                NetworkConfig n = new NetworkConfig(naString);
                if (wifiOnly && ConnectivityManager.isNetworkTypeMobile(n.type)) {
                    continue;
                }
                mNetworks.put(n.type, n);
            } catch (Exception e) {}
        }
        mUiAutomation = mInstrumentation.getUiAutomation();
        mShellPermissionIdentityAdopted = false;
    }

    @Override
    protected void tearDown() throws Exception {
        // Return WiFi to its original disabled state after tests that explicitly connect.
        if (mWifiConnectAttempted) {
            disconnectFromWifi(null);
        }
        if (cellConnectAttempted()) {
            disconnectFromCell();
        }
        dropShellPermissionIdentity();
        super.tearDown();
    }

    /**
     * Make sure WiFi is connected to an access point if it is not already. If
     * WiFi is enabled as a result of this function, it will be disabled
     * automatically in tearDown().
     */
    private Network ensureWifiConnected() {
        if (mWifiManager.isWifiEnabled()) {
            return getWifiNetwork();
        }
        mWifiConnectAttempted = true;
        return connectToWifi();
    }

    public void testIsNetworkTypeValid() {
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_MOBILE));
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_WIFI));
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_MOBILE_MMS));
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_MOBILE_SUPL));
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_MOBILE_DUN));
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_MOBILE_HIPRI));
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_WIMAX));
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_BLUETOOTH));
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_DUMMY));
        assertTrue(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.TYPE_ETHERNET));
        assertTrue(mCm.isNetworkTypeValid(ConnectivityManager.TYPE_MOBILE_FOTA));
        assertTrue(mCm.isNetworkTypeValid(ConnectivityManager.TYPE_MOBILE_IMS));
        assertTrue(mCm.isNetworkTypeValid(ConnectivityManager.TYPE_MOBILE_CBS));
        assertTrue(mCm.isNetworkTypeValid(ConnectivityManager.TYPE_WIFI_P2P));
        assertTrue(mCm.isNetworkTypeValid(ConnectivityManager.TYPE_MOBILE_IA));
        assertFalse(mCm.isNetworkTypeValid(-1));
        assertTrue(mCm.isNetworkTypeValid(0));
        assertTrue(mCm.isNetworkTypeValid(ConnectivityManager.MAX_NETWORK_TYPE));
        assertFalse(ConnectivityManager.isNetworkTypeValid(ConnectivityManager.MAX_NETWORK_TYPE+1));

        NetworkInfo[] ni = mCm.getAllNetworkInfo();

        for (NetworkInfo n: ni) {
            assertTrue(ConnectivityManager.isNetworkTypeValid(n.getType()));
        }

    }

    public void testSetNetworkPreference() {
        // getNetworkPreference() and setNetworkPreference() are both deprecated so they do
        // not preform any action.  Verify they are at least still callable.
        mCm.setNetworkPreference(mCm.getNetworkPreference());
    }

    public void testGetActiveNetworkInfo() {
        NetworkInfo ni = mCm.getActiveNetworkInfo();

        assertNotNull("You must have an active network connection to complete CTS", ni);
        assertTrue(ConnectivityManager.isNetworkTypeValid(ni.getType()));
        assertTrue(ni.getState() == State.CONNECTED);
    }

    public void testGetActiveNetwork() {
        Network network = mCm.getActiveNetwork();
        assertNotNull("You must have an active network connection to complete CTS", network);

        NetworkInfo ni = mCm.getNetworkInfo(network);
        assertNotNull("Network returned from getActiveNetwork was invalid", ni);

        // Similar to testGetActiveNetworkInfo above.
        assertTrue(ConnectivityManager.isNetworkTypeValid(ni.getType()));
        assertTrue(ni.getState() == State.CONNECTED);
    }

    public void testGetNetworkInfo() {
        for (int type = -1; type <= ConnectivityManager.MAX_NETWORK_TYPE+1; type++) {
            if (isSupported(type)) {
                NetworkInfo ni = mCm.getNetworkInfo(type);
                assertTrue("Info shouldn't be null for " + type, ni != null);
                State state = ni.getState();
                assertTrue("Bad state for " + type, State.UNKNOWN.ordinal() >= state.ordinal()
                           && state.ordinal() >= State.CONNECTING.ordinal());
                DetailedState ds = ni.getDetailedState();
                assertTrue("Bad detailed state for " + type,
                           DetailedState.FAILED.ordinal() >= ds.ordinal()
                           && ds.ordinal() >= DetailedState.IDLE.ordinal());
            } else {
                assertNull("Info should be null for " + type, mCm.getNetworkInfo(type));
            }
        }
    }

    public void testGetAllNetworkInfo() {
        NetworkInfo[] ni = mCm.getAllNetworkInfo();
        assertTrue(ni.length >= MIN_NUM_NETWORK_TYPES);
        for (int type = 0; type <= ConnectivityManager.MAX_NETWORK_TYPE; type++) {
            int desiredFoundCount = (isSupported(type) ? 1 : 0);
            int foundCount = 0;
            for (NetworkInfo i : ni) {
                if (i.getType() == type) foundCount++;
            }
            if (foundCount != desiredFoundCount) {
                Log.e(TAG, "failure in testGetAllNetworkInfo.  Dump of returned NetworkInfos:");
                for (NetworkInfo networkInfo : ni) Log.e(TAG, "  " + networkInfo);
            }
            assertTrue("Unexpected foundCount of " + foundCount + " for type " + type,
                    foundCount == desiredFoundCount);
        }
    }

    /**
     * Tests that connections can be opened on WiFi and cellphone networks,
     * and that they are made from different IP addresses.
     */
    @AppModeFull(reason = "Cannot get WifiManager in instant app mode")
    public void testOpenConnection() throws Exception {
        boolean canRunTest = mPackageManager.hasSystemFeature(FEATURE_WIFI)
                && mPackageManager.hasSystemFeature(FEATURE_TELEPHONY);
        if (!canRunTest) {
            Log.i(TAG,"testOpenConnection cannot execute unless device supports both WiFi "
                    + "and a cellular connection");
            return;
        }

        Network wifiNetwork = connectToWifi();
        Network cellNetwork = connectToCell();
        // This server returns the requestor's IP address as the response body.
        URL url = new URL("http://google-ipv6test.appspot.com/ip.js?fmt=text");
        String wifiAddressString = httpGet(wifiNetwork, url);
        String cellAddressString = httpGet(cellNetwork, url);

        assertFalse(String.format("Same address '%s' on two different networks (%s, %s)",
                wifiAddressString, wifiNetwork, cellNetwork),
                wifiAddressString.equals(cellAddressString));

        // Sanity check that the IP addresses that the requests appeared to come from
        // are actually on the respective networks.
        assertOnNetwork(wifiAddressString, wifiNetwork);
        assertOnNetwork(cellAddressString, cellNetwork);

        assertFalse("Unexpectedly equal: " + wifiNetwork, wifiNetwork.equals(cellNetwork));
    }

    private Network connectToCell() throws InterruptedException {
        if (cellConnectAttempted()) {
            throw new IllegalStateException("Already connected");
        }
        NetworkRequest cellRequest = new NetworkRequest.Builder()
                .addTransportType(TRANSPORT_CELLULAR)
                .addCapability(NET_CAPABILITY_INTERNET)
                .build();
        mCellNetworkCallback = new TestNetworkCallback();
        mCm.requestNetwork(cellRequest, mCellNetworkCallback);
        final Network cellNetwork = mCellNetworkCallback.waitForAvailable();
        assertNotNull("Cell network not available within timeout", cellNetwork);
        return cellNetwork;
    }

    private boolean cellConnectAttempted() {
        return mCellNetworkCallback != null;
    }

    private void disconnectFromCell() {
        if (!cellConnectAttempted()) {
            throw new IllegalStateException("Cell connection not attempted");
        }
        mCm.unregisterNetworkCallback(mCellNetworkCallback);
        mCellNetworkCallback = null;
    }

    /**
     * Performs a HTTP GET to the specified URL on the specified Network, and returns
     * the response body decoded as UTF-8.
     */
    private static String httpGet(Network network, URL httpUrl) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) network.openConnection(httpUrl);
        try {
            InputStream inputStream = connection.getInputStream();
            return Streams.readFully(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        } finally {
            connection.disconnect();
        }
    }

    private void assertOnNetwork(String adressString, Network network) throws UnknownHostException {
        InetAddress address = InetAddress.getByName(adressString);
        LinkProperties linkProperties = mCm.getLinkProperties(network);
        // To make sure that the request went out on the right network, check that
        // the IP address seen by the server is assigned to the expected network.
        // We can only do this for IPv6 addresses, because in IPv4 we will likely
        // have a private IPv4 address, and that won't match what the server sees.
        if (address instanceof Inet6Address) {
            assertContains(linkProperties.getAddresses(), address);
        }
    }

    private static<T> void assertContains(Collection<T> collection, T element) {
        assertTrue(element + " not found in " + collection, collection.contains(element));
    }

    private void assertStartUsingNetworkFeatureUnsupported(int networkType, String feature) {
        try {
            mCm.startUsingNetworkFeature(networkType, feature);
            fail("startUsingNetworkFeature is no longer supported in the current API version");
        } catch (UnsupportedOperationException expected) {}
    }

    private void assertStopUsingNetworkFeatureUnsupported(int networkType, String feature) {
        try {
            mCm.startUsingNetworkFeature(networkType, feature);
            fail("stopUsingNetworkFeature is no longer supported in the current API version");
        } catch (UnsupportedOperationException expected) {}
    }

    private void assertRequestRouteToHostUnsupported(int networkType, int hostAddress) {
        try {
            mCm.requestRouteToHost(networkType, hostAddress);
            fail("requestRouteToHost is no longer supported in the current API version");
        } catch (UnsupportedOperationException expected) {}
    }

    public void testStartUsingNetworkFeature() {

        final String invalidateFeature = "invalidateFeature";
        final String mmsFeature = "enableMMS";
        final int failureCode = -1;
        final int wifiOnlyStartFailureCode = PhoneConstants.APN_REQUEST_FAILED;
        final int wifiOnlyStopFailureCode = -1;

        assertStartUsingNetworkFeatureUnsupported(TYPE_MOBILE, invalidateFeature);
        assertStopUsingNetworkFeatureUnsupported(TYPE_MOBILE, invalidateFeature);
        assertStartUsingNetworkFeatureUnsupported(TYPE_WIFI, mmsFeature);
    }

    private boolean isSupported(int networkType) {
        return mNetworks.containsKey(networkType) ||
               (networkType == ConnectivityManager.TYPE_VPN) ||
               (networkType == ConnectivityManager.TYPE_ETHERNET &&
                       mContext.getSystemService(Context.ETHERNET_SERVICE) != null);
    }

    public void testIsNetworkSupported() {
        for (int type = -1; type <= ConnectivityManager.MAX_NETWORK_TYPE; type++) {
            boolean supported = mCm.isNetworkSupported(type);
            if (isSupported(type)) {
                assertTrue(supported);
            } else {
                assertFalse(supported);
            }
        }
    }

    public void testRequestRouteToHost() {
        for (int type = -1 ; type <= ConnectivityManager.MAX_NETWORK_TYPE; type++) {
            assertRequestRouteToHostUnsupported(type, HOST_ADDRESS);
        }
    }

    public void testTest() {
        mCm.getBackgroundDataSetting();
    }

    private NetworkRequest makeWifiNetworkRequest() {
        return new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .build();
    }

    /**
     * Exercises both registerNetworkCallback and unregisterNetworkCallback. This checks to
     * see if we get a callback for the TRANSPORT_WIFI transport type being available.
     *
     * <p>In order to test that a NetworkCallback occurs, we need some change in the network
     * state (either a transport or capability is now available). The most straightforward is
     * WiFi. We could add a version that uses the telephony data connection but it's not clear
     * that it would increase test coverage by much (how many devices have 3G radio but not Wifi?).
     */
    @AppModeFull(reason = "Cannot get WifiManager in instant app mode")
    public void testRegisterNetworkCallback() {
        if (!mPackageManager.hasSystemFeature(FEATURE_WIFI)) {
            Log.i(TAG, "testRegisterNetworkCallback cannot execute unless device supports WiFi");
            return;
        }

        // We will register for a WIFI network being available or lost.
        final TestNetworkCallback callback = new TestNetworkCallback();
        mCm.registerNetworkCallback(makeWifiNetworkRequest(), callback);

        final TestNetworkCallback defaultTrackingCallback = new TestNetworkCallback();
        mCm.registerDefaultNetworkCallback(defaultTrackingCallback);

        Network wifiNetwork = null;

        try {
            ensureWifiConnected();

            // Now we should expect to get a network callback about availability of the wifi
            // network even if it was already connected as a state-based action when the callback
            // is registered.
            wifiNetwork = callback.waitForAvailable();
            assertNotNull("Did not receive NetworkCallback.onAvailable for TRANSPORT_WIFI",
                    wifiNetwork);

            assertNotNull("Did not receive NetworkCallback.onAvailable for any default network",
                    defaultTrackingCallback.waitForAvailable());
        } catch (InterruptedException e) {
            fail("Broadcast receiver or NetworkCallback wait was interrupted.");
        } finally {
            mCm.unregisterNetworkCallback(callback);
            mCm.unregisterNetworkCallback(defaultTrackingCallback);
        }
    }

    /**
     * Tests both registerNetworkCallback and unregisterNetworkCallback similarly to
     * {@link #testRegisterNetworkCallback} except that a {@code PendingIntent} is used instead
     * of a {@code NetworkCallback}.
     */
    @AppModeFull(reason = "Cannot get WifiManager in instant app mode")
    public void testRegisterNetworkCallback_withPendingIntent() {
        if (!mPackageManager.hasSystemFeature(FEATURE_WIFI)) {
            Log.i(TAG, "testRegisterNetworkCallback cannot execute unless device supports WiFi");
            return;
        }

        // Create a ConnectivityActionReceiver that has an IntentFilter for our locally defined
        // action, NETWORK_CALLBACK_ACTION.
        IntentFilter filter = new IntentFilter();
        filter.addAction(NETWORK_CALLBACK_ACTION);

        ConnectivityActionReceiver receiver = new ConnectivityActionReceiver(
                ConnectivityManager.TYPE_WIFI, NetworkInfo.State.CONNECTED);
        mContext.registerReceiver(receiver, filter);

        // Create a broadcast PendingIntent for NETWORK_CALLBACK_ACTION.
        Intent intent = new Intent(NETWORK_CALLBACK_ACTION);
        PendingIntent pendingIntent = PendingIntent.getBroadcast(
                mContext, 0, intent, PendingIntent.FLAG_CANCEL_CURRENT);

        // We will register for a WIFI network being available or lost.
        mCm.registerNetworkCallback(makeWifiNetworkRequest(), pendingIntent);

        try {
            ensureWifiConnected();

            // Now we expect to get the Intent delivered notifying of the availability of the wifi
            // network even if it was already connected as a state-based action when the callback
            // is registered.
            assertTrue("Did not receive expected Intent " + intent + " for TRANSPORT_WIFI",
                    receiver.waitForState());
        } catch (InterruptedException e) {
            fail("Broadcast receiver or NetworkCallback wait was interrupted.");
        } finally {
            mCm.unregisterNetworkCallback(pendingIntent);
            pendingIntent.cancel();
            mContext.unregisterReceiver(receiver);
        }
    }

    /**
     * Exercises the requestNetwork with NetworkCallback API. This checks to
     * see if we get a callback for an INTERNET request.
     */
    @AppModeFull(reason = "CHANGE_NETWORK_STATE permission can't be granted to instant apps")
    public void testRequestNetworkCallback() {
        final TestNetworkCallback callback = new TestNetworkCallback();
        mCm.requestNetwork(new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build(), callback);

        try {
            // Wait to get callback for availability of internet
            Network internetNetwork = callback.waitForAvailable();
            assertNotNull("Did not receive NetworkCallback#onAvailable for INTERNET",
                    internetNetwork);
        } catch (InterruptedException e) {
            fail("NetworkCallback wait was interrupted.");
        } finally {
            mCm.unregisterNetworkCallback(callback);
        }
    }

    /**
     * Exercises the requestNetwork with NetworkCallback API with timeout - expected to
     * fail. Use WIFI and switch Wi-Fi off.
     */
    @AppModeFull(reason = "Cannot get WifiManager in instant app mode")
    public void testRequestNetworkCallback_onUnavailable() {
        final boolean previousWifiEnabledState = mWifiManager.isWifiEnabled();
        if (previousWifiEnabledState) {
            disconnectFromWifi(null);
        }

        final TestNetworkCallback callback = new TestNetworkCallback();
        mCm.requestNetwork(new NetworkRequest.Builder()
                .addTransportType(TRANSPORT_WIFI)
                .build(), callback, 100);

        try {
            // Wait to get callback for unavailability of requested network
            assertTrue("Did not receive NetworkCallback#onUnavailable",
                    callback.waitForUnavailable());
        } catch (InterruptedException e) {
            fail("NetworkCallback wait was interrupted.");
        } finally {
            mCm.unregisterNetworkCallback(callback);
            if (previousWifiEnabledState) {
                connectToWifi();
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

    private InetAddress getFirstV4Address(Network network) {
        LinkProperties linkProperties = mCm.getLinkProperties(network);
        for (InetAddress address : linkProperties.getAddresses()) {
            if (address instanceof Inet4Address) {
                return address;
            }
        }
        return null;
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

    private void testHttpRequest(Socket s) throws IOException {
        OutputStream out = s.getOutputStream();
        InputStream in = s.getInputStream();

        final byte[] requestBytes = HTTP_REQUEST.getBytes("UTF-8");
        byte[] responseBytes = new byte[4096];
        out.write(requestBytes);
        in.read(responseBytes);
        assertTrue(new String(responseBytes, "UTF-8").startsWith("HTTP/1.0 204 No Content\r\n"));
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

    /** Verify restricted networks cannot be requested. */
    @AppModeFull(reason = "CHANGE_NETWORK_STATE permission can't be granted to instant apps")
    public void testRestrictedNetworks() {
        // Verify we can request unrestricted networks:
        NetworkRequest request = new NetworkRequest.Builder()
                .addCapability(NET_CAPABILITY_INTERNET).build();
        NetworkCallback callback = new NetworkCallback();
        mCm.requestNetwork(request, callback);
        mCm.unregisterNetworkCallback(callback);
        // Verify we cannot request restricted networks:
        request = new NetworkRequest.Builder().addCapability(NET_CAPABILITY_IMS).build();
        callback = new NetworkCallback();
        try {
            mCm.requestNetwork(request, callback);
            fail("No exception thrown when restricted network requested.");
        } catch (SecurityException expected) {}
    }

    // Returns "true", "false" or "none"
    private String getWifiMeteredStatus(String ssid) throws Exception {
        // Interestingly giving the SSID as an argument to list wifi-networks
        // only works iff the network in question has the "false" policy.
        // Also unfortunately runShellCommand does not pass the command to the interpreter
        // so it's not possible to | grep the ssid.
        final String command = "cmd netpolicy list wifi-networks";
        final String policyString = runShellCommand(mInstrumentation, command);

        final Matcher m = Pattern.compile("^" + ssid + ";(true|false|none)$",
                Pattern.MULTILINE | Pattern.UNIX_LINES).matcher(policyString);
        if (!m.find()) {
            fail("Unexpected format from cmd netpolicy");
        }
        return m.group(1);
    }

    // metered should be "true", "false" or "none"
    private void setWifiMeteredStatus(String ssid, String metered) throws Exception {
        final String setCommand = "cmd netpolicy set metered-network " + ssid + " " + metered;
        runShellCommand(mInstrumentation, setCommand);
        assertEquals(getWifiMeteredStatus(ssid), metered);
    }

    private String unquoteSSID(String ssid) {
        // SSID is returned surrounded by quotes if it can be decoded as UTF-8.
        // Otherwise it's guaranteed not to start with a quote.
        if (ssid.charAt(0) == '"') {
            return ssid.substring(1, ssid.length() - 1);
        } else {
            return ssid;
        }
    }

    private void waitForActiveNetworkMetered(boolean requestedMeteredness) throws Exception {
        final CountDownLatch latch = new CountDownLatch(1);
        final NetworkCallback networkCallback = new NetworkCallback() {
            @Override
            public void onCapabilitiesChanged(Network network, NetworkCapabilities nc) {
                final boolean metered = !nc.hasCapability(NET_CAPABILITY_NOT_METERED);
                if (metered == requestedMeteredness) {
                    latch.countDown();
                }
            }
        };
        // Registering a callback here guarantees onCapabilitiesChanged is called immediately
        // with the current setting. Therefore, if the setting has already been changed,
        // this method will return right away, and if not it will wait for the setting to change.
        mCm.registerDefaultNetworkCallback(networkCallback);
        if (!latch.await(NETWORK_CHANGE_METEREDNESS_TIMEOUT, TimeUnit.MILLISECONDS)) {
            fail("Timed out waiting for active network metered status to change to "
                 + requestedMeteredness + " ; network = " + mCm.getActiveNetwork());
        }
        mCm.unregisterNetworkCallback(networkCallback);
    }

    private void assertMultipathPreferenceIsEventually(Network network, int oldValue,
            int expectedValue) {
        // Sanity check : if oldValue == expectedValue, there is no way to guarantee the test
        // is not flaky.
        assertNotSame(oldValue, expectedValue);

        for (int i = 0; i < NUM_TRIES_MULTIPATH_PREF_CHECK; ++i) {
            final int actualValue = mCm.getMultipathPreference(network);
            if (actualValue == expectedValue) {
                return;
            }
            if (actualValue != oldValue) {
                fail("Multipath preference is neither previous (" + oldValue
                        + ") nor expected (" + expectedValue + ")");
            }
            SystemClock.sleep(INTERVAL_MULTIPATH_PREF_CHECK_MS);
        }
        fail("Timed out waiting for multipath preference to change. expected = "
                + expectedValue + " ; actual = " + mCm.getMultipathPreference(network));
    }

    private int getCurrentMeteredMultipathPreference(ContentResolver resolver) {
        final String rawMeteredPref = Settings.Global.getString(resolver,
                NETWORK_METERED_MULTIPATH_PREFERENCE);
        return TextUtils.isEmpty(rawMeteredPref)
            ? mContext.getResources().getInteger(R.integer.config_networkMeteredMultipathPreference)
            : Integer.parseInt(rawMeteredPref);
    }

    private int findNextPrefValue(ContentResolver resolver) {
        // A bit of a nuclear hammer, but race conditions in CTS are bad. To be able to
        // detect a correct setting value without race conditions, the next pref must
        // be a valid value (range 0..3) that is different from the old setting of the
        // metered preference and from the unmetered preference.
        final int meteredPref = getCurrentMeteredMultipathPreference(resolver);
        final int unmeteredPref = ConnectivityManager.MULTIPATH_PREFERENCE_UNMETERED;
        if (0 != meteredPref && 0 != unmeteredPref) return 0;
        if (1 != meteredPref && 1 != unmeteredPref) return 1;
        return 2;
    }

    /**
     * Verify that getMultipathPreference does return appropriate values
     * for metered and unmetered networks.
     */
    @AppModeFull(reason = "Cannot get WifiManager in instant app mode")
    public void testGetMultipathPreference() throws Exception {
        final ContentResolver resolver = mContext.getContentResolver();
        final Network network = ensureWifiConnected();
        final String ssid = unquoteSSID(mWifiManager.getConnectionInfo().getSSID());
        final String oldMeteredSetting = getWifiMeteredStatus(ssid);
        final String oldMeteredMultipathPreference = Settings.Global.getString(
                resolver, NETWORK_METERED_MULTIPATH_PREFERENCE);
        try {
            final int initialMeteredPreference = getCurrentMeteredMultipathPreference(resolver);
            int newMeteredPreference = findNextPrefValue(resolver);
            Settings.Global.putString(resolver, NETWORK_METERED_MULTIPATH_PREFERENCE,
                    Integer.toString(newMeteredPreference));
            setWifiMeteredStatus(ssid, "true");
            waitForActiveNetworkMetered(true);
            assertEquals(mCm.getNetworkCapabilities(network).hasCapability(
                    NET_CAPABILITY_NOT_METERED), false);
            assertMultipathPreferenceIsEventually(network, initialMeteredPreference,
                    newMeteredPreference);

            final int oldMeteredPreference = newMeteredPreference;
            newMeteredPreference = findNextPrefValue(resolver);
            Settings.Global.putString(resolver, NETWORK_METERED_MULTIPATH_PREFERENCE,
                    Integer.toString(newMeteredPreference));
            assertEquals(mCm.getNetworkCapabilities(network).hasCapability(
                    NET_CAPABILITY_NOT_METERED), false);
            assertMultipathPreferenceIsEventually(network,
                    oldMeteredPreference, newMeteredPreference);

            setWifiMeteredStatus(ssid, "false");
            waitForActiveNetworkMetered(false);
            assertEquals(mCm.getNetworkCapabilities(network).hasCapability(
                    NET_CAPABILITY_NOT_METERED), true);
            assertMultipathPreferenceIsEventually(network, newMeteredPreference,
                    ConnectivityManager.MULTIPATH_PREFERENCE_UNMETERED);
        } finally {
            Settings.Global.putString(resolver, NETWORK_METERED_MULTIPATH_PREFERENCE,
                    oldMeteredMultipathPreference);
            setWifiMeteredStatus(ssid, oldMeteredSetting);
        }
    }

    // TODO: move the following socket keep alive test to dedicated test class.
    /**
     * Callback used in tcp keepalive offload that allows caller to wait callback fires.
     */
    private static class TestSocketKeepaliveCallback extends SocketKeepalive.Callback {
        public enum CallbackType { ON_STARTED, ON_STOPPED, ON_ERROR };

        public static class CallbackValue {
            public final CallbackType callbackType;
            public final int error;

            private CallbackValue(final CallbackType type, final int error) {
                this.callbackType = type;
                this.error = error;
            }

            public static class OnStartedCallback extends CallbackValue {
                OnStartedCallback() { super(CallbackType.ON_STARTED, 0); }
            }

            public static class OnStoppedCallback extends CallbackValue {
                OnStoppedCallback() { super(CallbackType.ON_STOPPED, 0); }
            }

            public static class OnErrorCallback extends CallbackValue {
                OnErrorCallback(final int error) { super(CallbackType.ON_ERROR, error); }
            }

            @Override
            public boolean equals(Object o) {
                return o.getClass() == this.getClass()
                        && this.callbackType == ((CallbackValue) o).callbackType
                        && this.error == ((CallbackValue) o).error;
            }

            @Override
            public String toString() {
                return String.format("%s(%s, %d)", getClass().getSimpleName(), callbackType, error);
            }
        }

        private final LinkedBlockingQueue<CallbackValue> mCallbacks = new LinkedBlockingQueue<>();

        @Override
        public void onStarted() {
            mCallbacks.add(new CallbackValue.OnStartedCallback());
        }

        @Override
        public void onStopped() {
            mCallbacks.add(new CallbackValue.OnStoppedCallback());
        }

        @Override
        public void onError(final int error) {
            mCallbacks.add(new CallbackValue.OnErrorCallback(error));
        }

        public CallbackValue pollCallback() {
            try {
                return mCallbacks.poll(KEEPALIVE_CALLBACK_TIMEOUT_MS,
                        TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                fail("Callback not seen after " + KEEPALIVE_CALLBACK_TIMEOUT_MS + " ms");
            }
            return null;
        }
        private void expectCallback(CallbackValue expectedCallback) {
            final CallbackValue actualCallback = pollCallback();
            assertEquals(expectedCallback, actualCallback);
        }

        public void expectStarted() {
            expectCallback(new CallbackValue.OnStartedCallback());
        }

        public void expectStopped() {
            expectCallback(new CallbackValue.OnStoppedCallback());
        }

        public void expectError(int error) {
            expectCallback(new CallbackValue.OnErrorCallback(error));
        }
    }

    private InetAddress getAddrByName(final String hostname, final int family) throws Exception {
        final InetAddress[] allAddrs = InetAddress.getAllByName(hostname);
        for (InetAddress addr : allAddrs) {
            if (family == AF_INET && addr instanceof Inet4Address) return addr;

            if (family == AF_INET6 && addr instanceof Inet6Address) return addr;

            if (family == AF_UNSPEC) return addr;
        }
        return null;
    }

    private Socket getConnectedSocket(final Network network, final String host, final int port,
            final int socketTimeOut, final int family) throws Exception {
        final Socket s = network.getSocketFactory().createSocket();
        try {
            final InetAddress addr = getAddrByName(host, family);
            if (addr == null) fail("Fail to get destination address for " + family);

            final InetSocketAddress sockAddr = new InetSocketAddress(addr, port);
            s.setSoTimeout(socketTimeOut);
            s.connect(sockAddr, CONNECT_TIMEOUT_MS);
        } catch (Exception e) {
            s.close();
            throw e;
        }
        return s;
    }

    private int getSupportedKeepalivesFromRes() throws Exception {
        final Network network = ensureWifiConnected();
        final NetworkCapabilities nc = mCm.getNetworkCapabilities(network);

        // Get number of supported concurrent keepalives for testing network.
        final int[] keepalivesPerTransport = KeepaliveUtils.getSupportedKeepalives(mContext);
        return KeepaliveUtils.getSupportedKeepalivesForNetworkCapabilities(
                keepalivesPerTransport, nc);
    }

    private void adoptShellPermissionIdentity() {
        mUiAutomation.adoptShellPermissionIdentity();
        mShellPermissionIdentityAdopted = true;
    }

    private void dropShellPermissionIdentity() {
        if (mShellPermissionIdentityAdopted) {
            mUiAutomation.dropShellPermissionIdentity();
            mShellPermissionIdentityAdopted = false;
        }
    }

    private static boolean isTcpKeepaliveSupportedByKernel() {
        final String kVersionString = VintfRuntimeInfo.getKernelVersion();
        return compareMajorMinorVersion(kVersionString, "4.8") >= 0;
    }

    private static Pair<Integer, Integer> getVersionFromString(String version) {
        // Only gets major and minor number of the version string.
        final Pattern versionPattern = Pattern.compile("^(\\d+)(\\.(\\d+))?.*");
        final Matcher m = versionPattern.matcher(version);
        if (m.matches()) {
            final int major = Integer.parseInt(m.group(1));
            final int minor = TextUtils.isEmpty(m.group(3)) ? 0 : Integer.parseInt(m.group(3));
            return new Pair<>(major, minor);
        } else {
            return new Pair<>(0, 0);
        }
    }

    // TODO: Move to util class.
    private static int compareMajorMinorVersion(final String s1, final String s2) {
        final Pair<Integer, Integer> v1 = getVersionFromString(s1);
        final Pair<Integer, Integer> v2 = getVersionFromString(s2);

        if (v1.first == v2.first) {
            return Integer.compare(v1.second, v2.second);
        } else {
            return Integer.compare(v1.first, v2.first);
        }
    }

    /**
     * Verifies that version string compare logic returns expected result for various cases.
     * Note that only major and minor number are compared.
     */
    public void testMajorMinorVersionCompare() {
        assertEquals(0, compareMajorMinorVersion("4.8.1", "4.8"));
        assertEquals(1, compareMajorMinorVersion("4.9", "4.8.1"));
        assertEquals(1, compareMajorMinorVersion("5.0", "4.8"));
        assertEquals(1, compareMajorMinorVersion("5", "4.8"));
        assertEquals(0, compareMajorMinorVersion("5", "5.0"));
        assertEquals(1, compareMajorMinorVersion("5-beta1", "4.8"));
        assertEquals(0, compareMajorMinorVersion("4.8.0.0", "4.8"));
        assertEquals(0, compareMajorMinorVersion("4.8-RC1", "4.8"));
        assertEquals(0, compareMajorMinorVersion("4.8", "4.8"));
        assertEquals(-1, compareMajorMinorVersion("3.10", "4.8.0"));
        assertEquals(-1, compareMajorMinorVersion("4.7.10.10", "4.8"));
    }

    /**
     * Verifies that the keepalive API cannot create any keepalive when the maximum number of
     * keepalives is set to 0.
     */
    @AppModeFull(reason = "Cannot get WifiManager in instant app mode")
    public void testKeepaliveUnsupported() throws Exception {
        if (getSupportedKeepalivesFromRes() != 0) return;

        adoptShellPermissionIdentity();

        assertEquals(0, createConcurrentSocketKeepalives(1, 0));
        assertEquals(0, createConcurrentSocketKeepalives(0, 1));

        dropShellPermissionIdentity();
    }

    @AppModeFull(reason = "Cannot get WifiManager in instant app mode")
    public void testCreateTcpKeepalive() throws Exception {
        adoptShellPermissionIdentity();

        if (getSupportedKeepalivesFromRes() == 0) return;
        // If kernel < 4.8 then it doesn't support TCP keepalive, but it might still support
        // NAT-T keepalive. If keepalive limits from resource overlay is not zero, TCP keepalive
        // needs to be supported except if the kernel doesn't support it.
        if (!isTcpKeepaliveSupportedByKernel()) {
            // Sanity check to ensure the callback result is expected.
            assertEquals(0, createConcurrentSocketKeepalives(0, 1));
            Log.i(TAG, "testCreateTcpKeepalive is skipped for kernel "
                    + VintfRuntimeInfo.getKernelVersion());
            return;
        }

        final Network network = ensureWifiConnected();
        final byte[] requestBytes = HTTP_REQUEST.getBytes("UTF-8");
        // So far only ipv4 tcp keepalive offload is supported.
        // TODO: add test case for ipv6 tcp keepalive offload when it is supported.
        try (Socket s = getConnectedSocket(network, TEST_HOST, HTTP_PORT,
                KEEPALIVE_SOCKET_TIMEOUT_MS, AF_INET)) {

            // Should able to start keep alive offload when socket is idle.
            final Executor executor = mContext.getMainExecutor();
            final TestSocketKeepaliveCallback callback = new TestSocketKeepaliveCallback();
            try (SocketKeepalive sk = mCm.createSocketKeepalive(network, s, executor, callback)) {
                sk.start(MIN_KEEPALIVE_INTERVAL);
                callback.expectStarted();

                // App should not able to write during keepalive offload.
                final OutputStream out = s.getOutputStream();
                try {
                    out.write(requestBytes);
                    fail("Should not able to write");
                } catch (IOException e) { }
                // App should not able to read during keepalive offload.
                final InputStream in = s.getInputStream();
                byte[] responseBytes = new byte[4096];
                try {
                    in.read(responseBytes);
                    fail("Should not able to read");
                } catch (IOException e) { }

                // Stop.
                sk.stop();
                callback.expectStopped();
            }

            // Ensure socket is still connected.
            assertTrue(s.isConnected());
            assertFalse(s.isClosed());

            // Let socket be not idle.
            try {
                final OutputStream out = s.getOutputStream();
                out.write(requestBytes);
            } catch (IOException e) {
                fail("Failed to write data " + e);
            }
            // Make sure response data arrives.
            final MessageQueue fdHandlerQueue = Looper.getMainLooper().getQueue();
            final FileDescriptor fd = s.getFileDescriptor$();
            final CountDownLatch mOnReceiveLatch = new CountDownLatch(1);
            fdHandlerQueue.addOnFileDescriptorEventListener(fd, EVENT_INPUT, (readyFd, events) -> {
                mOnReceiveLatch.countDown();
                return 0; // Unregister listener.
            });
            if (!mOnReceiveLatch.await(2, TimeUnit.SECONDS)) {
                fdHandlerQueue.removeOnFileDescriptorEventListener(fd);
                fail("Timeout: no response data");
            }

            // Should get ERROR_SOCKET_NOT_IDLE because there is still data in the receive queue
            // that has not been read.
            try (SocketKeepalive sk = mCm.createSocketKeepalive(network, s, executor, callback)) {
                sk.start(MIN_KEEPALIVE_INTERVAL);
                callback.expectError(SocketKeepalive.ERROR_SOCKET_NOT_IDLE);
            }
        }
    }

    /**
     * Creates concurrent keepalives until the specified counts of each type of keepalives are
     * reached or the expected error callbacks are received for each type of keepalives.
     *
     * @return the total number of keepalives created.
     */
    private int createConcurrentSocketKeepalives(int nattCount, int tcpCount) throws Exception {
        final Network network = ensureWifiConnected();

        final ArrayList<SocketKeepalive> kalist = new ArrayList<>();
        final TestSocketKeepaliveCallback callback = new TestSocketKeepaliveCallback();
        final Executor executor = mContext.getMainExecutor();

        // Create concurrent TCP keepalives.
        for (int i = 0; i < tcpCount; i++) {
            // Assert that TCP connections can be established on wifi. The file descriptor of tcp
            // sockets will be duplicated and kept valid in service side if the keepalives are
            // successfully started.
            try (Socket tcpSocket = getConnectedSocket(network, TEST_HOST, HTTP_PORT,
                        0 /* Unused */, AF_INET)) {
                final SocketKeepalive ka = mCm.createSocketKeepalive(network, tcpSocket, executor,
                        callback);
                ka.start(MIN_KEEPALIVE_INTERVAL);
                TestSocketKeepaliveCallback.CallbackValue cv = callback.pollCallback();
                assertNotNull(cv);
                if (cv.callbackType == TestSocketKeepaliveCallback.CallbackType.ON_ERROR) {
                    if (i == 0 && cv.error == SocketKeepalive.ERROR_UNSUPPORTED) {
                        // Unsupported.
                        break;
                    } else if (i != 0 && cv.error == SocketKeepalive.ERROR_INSUFFICIENT_RESOURCES) {
                        // Limit reached.
                        break;
                    }
                }
                if (cv.callbackType == TestSocketKeepaliveCallback.CallbackType.ON_STARTED) {
                    kalist.add(ka);
                } else {
                    fail("Unexpected error when creating " + (i + 1) + " TCP keepalives: " + cv);
                }
            }
        }

        // Assert that a Nat-T socket can be created.
        final IpSecManager mIpSec = (IpSecManager) mContext.getSystemService(Context.IPSEC_SERVICE);
        final UdpEncapsulationSocket nattSocket = mIpSec.openUdpEncapsulationSocket();

        final InetAddress srcAddr = getFirstV4Address(network);
        final InetAddress dstAddr = getAddrByName(TEST_HOST, AF_INET);
        assertNotNull(srcAddr);
        assertNotNull(dstAddr);

        // Test concurrent Nat-T keepalives.
        for (int i = 0; i < nattCount; i++) {
            final SocketKeepalive ka = mCm.createSocketKeepalive(network, nattSocket,
                    srcAddr, dstAddr, executor, callback);
            ka.start(MIN_KEEPALIVE_INTERVAL);
            TestSocketKeepaliveCallback.CallbackValue cv = callback.pollCallback();
            assertNotNull(cv);
            if (cv.callbackType == TestSocketKeepaliveCallback.CallbackType.ON_ERROR) {
                if (i == 0 && cv.error == SocketKeepalive.ERROR_UNSUPPORTED) {
                    // Unsupported.
                    break;
                } else if (i != 0 && cv.error == SocketKeepalive.ERROR_INSUFFICIENT_RESOURCES) {
                    // Limit reached.
                    break;
                }
            }
            if (cv.callbackType == TestSocketKeepaliveCallback.CallbackType.ON_STARTED) {
                kalist.add(ka);
            } else {
                fail("Unexpected error when creating " + (i + 1) + " Nat-T keepalives: " + cv);
            }
        }

        final int ret = kalist.size();

        // Clean up.
        for (final SocketKeepalive ka : kalist) {
            ka.stop();
            callback.expectStopped();
        }
        kalist.clear();
        nattSocket.close();

        return ret;
    }

    /**
     * Verifies that the concurrent keepalive slots meet the minimum requirement, and don't
     * get leaked after iterations.
     */
    @AppModeFull(reason = "Cannot get WifiManager in instant app mode")
    public void testSocketKeepaliveLimit() throws Exception {
        final int supported = getSupportedKeepalivesFromRes();
        if (supported == 0) {
            return;
        }

        adoptShellPermissionIdentity();

        // Verifies that the supported keepalive slots meet MIN_SUPPORTED_KEEPALIVE_COUNT.
        assertGreaterOrEqual(supported, KeepaliveUtils.MIN_SUPPORTED_KEEPALIVE_COUNT);

        // Verifies that Nat-T keepalives can be established.
        assertEquals(supported, createConcurrentSocketKeepalives(supported + 1, 0));
        // Verifies that keepalives don't get leaked in second round.
        assertEquals(supported, createConcurrentSocketKeepalives(supported + 1, 0));

        // If kernel < 4.8 then it doesn't support TCP keepalive, but it might still support
        // NAT-T keepalive. Test below cases only if TCP keepalive is supported by kernel.
        if (isTcpKeepaliveSupportedByKernel()) {
            assertEquals(supported, createConcurrentSocketKeepalives(0, supported + 1));

            // Verifies that different types can be established at the same time.
            assertEquals(supported, createConcurrentSocketKeepalives(
                    supported / 2, supported - supported / 2));

            // Verifies that keepalives don't get leaked in second round.
            assertEquals(supported, createConcurrentSocketKeepalives(0, supported + 1));
            assertEquals(supported, createConcurrentSocketKeepalives(
                    supported / 2, supported - supported / 2));
        }

        dropShellPermissionIdentity();
    }

    /**
     * Verifies that the keepalive slots are limited as customized for unprivileged requests.
     */
    @AppModeFull(reason = "Cannot get WifiManager in instant app mode")
    public void testSocketKeepaliveUnprivileged() throws Exception {
        final int supported = getSupportedKeepalivesFromRes();
        if (supported == 0) {
            return;
        }

        final int allowedUnprivilegedPerUid = mContext.getResources().getInteger(
                R.integer.config_allowedUnprivilegedKeepalivePerUid);
        final int reservedPrivilegedSlots = mContext.getResources().getInteger(
                R.integer.config_reservedPrivilegedKeepaliveSlots);
        // Verifies that unprivileged request per uid cannot exceed the limit customized in the
        // resource. Currently, unprivileged keepalive slots are limited to Nat-T only, this test
        // does not apply to TCP.
        assertGreaterOrEqual(supported, reservedPrivilegedSlots);
        assertGreaterOrEqual(supported, allowedUnprivilegedPerUid);
        final int expectedUnprivileged =
                Math.min(allowedUnprivilegedPerUid, supported - reservedPrivilegedSlots);
        assertEquals(expectedUnprivileged, createConcurrentSocketKeepalives(supported + 1, 0));
    }

    private static void assertGreaterOrEqual(long greater, long lesser) {
        assertTrue("" + greater + " expected to be greater than or equal to " + lesser,
                greater >= lesser);
    }
}
