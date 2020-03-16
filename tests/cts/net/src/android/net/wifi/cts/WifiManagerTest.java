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

package android.net.wifi.cts;

import static android.net.NetworkCapabilities.TRANSPORT_WIFI;
import static android.net.wifi.WifiConfiguration.INVALID_NETWORK_ID;
import static android.net.wifi.WifiManager.TrafficStateCallback.DATA_ACTIVITY_INOUT;

import static com.google.common.truth.Truth.assertWithMessage;

import static org.junit.Assert.assertNotEquals;

import android.app.UiAutomation;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.util.MacAddressUtils;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.MacAddress;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.wifi.ScanResult;
import android.net.wifi.SoftApConfiguration;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiManager.WifiLock;
import android.net.wifi.WifiNetworkConnectionStatistics;
import android.net.wifi.hotspot2.ConfigParser;
import android.net.wifi.hotspot2.PasspointConfiguration;
import android.os.Process;
import android.os.SystemClock;
import android.os.UserHandle;
import android.platform.test.annotations.AppModeFull;
import android.provider.Settings;
import android.support.test.uiautomator.UiDevice;
import android.telephony.TelephonyManager;
import android.test.AndroidTestCase;
import android.text.TextUtils;
import android.util.ArraySet;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.compatibility.common.util.PollingCheck;
import com.android.compatibility.common.util.ShellIdentityUtils;
import com.android.compatibility.common.util.SystemUtil;
import com.android.compatibility.common.util.ThrowingRunnable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@AppModeFull(reason = "Cannot get WifiManager in instant app mode")
public class WifiManagerTest extends AndroidTestCase {
    private static class MySync {
        int expectedState = STATE_NULL;
    }

    private WifiManager mWifiManager;
    private ConnectivityManager mConnectivityManager;
    private WifiLock mWifiLock;
    private static MySync mMySync;
    private List<ScanResult> mScanResults = null;
    private NetworkInfo mNetworkInfo;
    private final Object mLock = new Object();
    private UiDevice mUiDevice;
    private boolean mWasVerboseLoggingEnabled;

    // Please refer to WifiManager
    private static final int MIN_RSSI = -100;
    private static final int MAX_RSSI = -55;

    private static final int STATE_NULL = 0;
    private static final int STATE_WIFI_CHANGING = 1;
    private static final int STATE_WIFI_ENABLED = 2;
    private static final int STATE_WIFI_DISABLED = 3;
    private static final int STATE_SCANNING = 4;
    private static final int STATE_SCAN_DONE = 5;

    private static final String TAG = "WifiManagerTest";
    private static final String SSID1 = "\"WifiManagerTest\"";
    // A full single scan duration is about 6-7 seconds if country code is set
    // to US. If country code is set to world mode (00), we would expect a scan
    // duration of roughly 8 seconds. So we set scan timeout as 9 seconds here.
    private static final int SCAN_TIMEOUT_MSEC = 9000;
    private static final int TIMEOUT_MSEC = 6000;
    private static final int WAIT_MSEC = 60;
    private static final int DURATION = 10_000;
    private static final int DURATION_SCREEN_TOGGLE = 2000;
    private static final int DURATION_SETTINGS_TOGGLE = 1_000;
    private static final int WIFI_SCAN_TEST_INTERVAL_MILLIS = 60 * 1000;
    private static final int WIFI_SCAN_TEST_CACHE_DELAY_MILLIS = 3 * 60 * 1000;
    private static final int WIFI_SCAN_TEST_ITERATIONS = 5;

    private static final int ENFORCED_NUM_NETWORK_SUGGESTIONS_PER_APP = 50;

    private static final String TEST_PAC_URL = "http://www.example.com/proxy.pac";
    private static final String MANAGED_PROVISIONING_PACKAGE_NAME
            = "com.android.managedprovisioning";

    private static final String TEST_SSID_UNQUOTED = "testSsid1";
    private static final MacAddress TEST_MAC = MacAddress.fromString("aa:bb:cc:dd:ee:ff");
    private static final String TEST_PASSPHRASE = "passphrase";
    private static final String PASSPOINT_INSTALLATION_FILE_WITH_CA_CERT =
            "assets/ValidPasspointProfile.base64";
    private static final String TYPE_WIFI_CONFIG = "application/x-wifi-config";

    private IntentFilter mIntentFilter;
    private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            final String action = intent.getAction();
            if (action.equals(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION)) {

                synchronized (mMySync) {
                    if (intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false)) {
                        mScanResults = mWifiManager.getScanResults();
                    } else {
                        mScanResults = null;
                    }
                    mMySync.expectedState = STATE_SCAN_DONE;
                    mMySync.notifyAll();
                }
            } else if (action.equals(WifiManager.WIFI_STATE_CHANGED_ACTION)) {
                int newState = intent.getIntExtra(WifiManager.EXTRA_WIFI_STATE,
                        WifiManager.WIFI_STATE_UNKNOWN);
                synchronized (mMySync) {
                    if (newState == WifiManager.WIFI_STATE_ENABLED) {
                        Log.d(TAG, "*** New WiFi state is ENABLED ***");
                        mMySync.expectedState = STATE_WIFI_ENABLED;
                        mMySync.notifyAll();
                    } else if (newState == WifiManager.WIFI_STATE_DISABLED) {
                        Log.d(TAG, "*** New WiFi state is DISABLED ***");
                        mMySync.expectedState = STATE_WIFI_DISABLED;
                        mMySync.notifyAll();
                    }
                }
            } else if (action.equals(WifiManager.NETWORK_STATE_CHANGED_ACTION)) {
                synchronized (mMySync) {
                    mNetworkInfo =
                            (NetworkInfo) intent.getParcelableExtra(WifiManager.EXTRA_NETWORK_INFO);
                    if (mNetworkInfo.getState() == NetworkInfo.State.CONNECTED)
                        mMySync.notifyAll();
                }
            }
        }
    };

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        mMySync = new MySync();
        mIntentFilter = new IntentFilter();
        mIntentFilter.addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION);
        mIntentFilter.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        mIntentFilter.addAction(WifiManager.SUPPLICANT_CONNECTION_CHANGE_ACTION);
        mIntentFilter.addAction(WifiManager.SUPPLICANT_STATE_CHANGED_ACTION);
        mIntentFilter.addAction(WifiManager.WIFI_STATE_CHANGED_ACTION);
        mIntentFilter.addAction(WifiManager.RSSI_CHANGED_ACTION);
        mIntentFilter.addAction(WifiManager.NETWORK_IDS_CHANGED_ACTION);
        mIntentFilter.addAction(WifiManager.ACTION_PICK_WIFI_NETWORK);

        mContext.registerReceiver(mReceiver, mIntentFilter);
        mWifiManager = (WifiManager) getContext().getSystemService(Context.WIFI_SERVICE);
        mConnectivityManager = getContext().getSystemService(ConnectivityManager.class);
        assertNotNull(mWifiManager);

        // turn on verbose logging for tests
        mWasVerboseLoggingEnabled = ShellIdentityUtils.invokeWithShellPermissions(
                () -> mWifiManager.isVerboseLoggingEnabled());
        ShellIdentityUtils.invokeWithShellPermissions(
                () -> mWifiManager.setVerboseLoggingEnabled(true));

        mWifiLock = mWifiManager.createWifiLock(TAG);
        mWifiLock.acquire();
        if (!mWifiManager.isWifiEnabled())
            setWifiEnabled(true);
        mUiDevice = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
        turnScreenOnNoDelay();
        Thread.sleep(DURATION);
        assertTrue(mWifiManager.isWifiEnabled());
        synchronized (mMySync) {
            mMySync.expectedState = STATE_NULL;
        }

        List<WifiConfiguration> savedNetworks = ShellIdentityUtils.invokeWithShellPermissions(
                mWifiManager::getConfiguredNetworks);
        assertFalse("Need at least one saved network", savedNetworks.isEmpty());
    }

    @Override
    protected void tearDown() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            super.tearDown();
            return;
        }
        if (!mWifiManager.isWifiEnabled())
            setWifiEnabled(true);
        mWifiLock.release();
        mContext.unregisterReceiver(mReceiver);
        ShellIdentityUtils.invokeWithShellPermissions(
                () -> mWifiManager.setVerboseLoggingEnabled(mWasVerboseLoggingEnabled));
        Thread.sleep(DURATION);
        super.tearDown();
    }

    private void setWifiEnabled(boolean enable) throws Exception {
        synchronized (mMySync) {
            if (mWifiManager.isWifiEnabled() != enable) {
                // the new state is different, we expect it to change
                mMySync.expectedState = STATE_WIFI_CHANGING;
            } else {
                mMySync.expectedState = (enable ? STATE_WIFI_ENABLED : STATE_WIFI_DISABLED);
            }
            // now trigger the change using shell commands.
            SystemUtil.runShellCommand("svc wifi " + (enable ? "enable" : "disable"));
            waitForExpectedWifiState(enable);
        }
    }

    private void waitForExpectedWifiState(boolean enabled) throws InterruptedException {
        synchronized (mMySync) {
            long timeout = System.currentTimeMillis() + TIMEOUT_MSEC;
            int expected = (enabled ? STATE_WIFI_ENABLED : STATE_WIFI_DISABLED);
            while (System.currentTimeMillis() < timeout
                    && mMySync.expectedState != expected) {
                mMySync.wait(WAIT_MSEC);
            }
        }
    }

    // Get the current scan status from sticky broadcast.
    private boolean isScanCurrentlyAvailable() {
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(WifiManager.ACTION_WIFI_SCAN_AVAILABILITY_CHANGED);
        Intent intent = mContext.registerReceiver(null, intentFilter);
        assertNotNull(intent);
        if (intent.getAction().equals(WifiManager.ACTION_WIFI_SCAN_AVAILABILITY_CHANGED)) {
            return intent.getBooleanExtra(WifiManager.EXTRA_SCAN_AVAILABLE, false);
        }
        return false;
    }

    private void startScan() throws Exception {
        synchronized (mMySync) {
            mMySync.expectedState = STATE_SCANNING;
            mScanResults = null;
            assertTrue(mWifiManager.startScan());
            long timeout = System.currentTimeMillis() + SCAN_TIMEOUT_MSEC;
            while (System.currentTimeMillis() < timeout && mMySync.expectedState == STATE_SCANNING)
                mMySync.wait(WAIT_MSEC);
        }
    }

    private void waitForNetworkInfoState(NetworkInfo.State state) throws Exception {
        synchronized (mMySync) {
            if (mNetworkInfo.getState() == state) return;
            long timeout = System.currentTimeMillis() + TIMEOUT_MSEC;
            while (System.currentTimeMillis() < timeout
                    && mNetworkInfo.getState() != state)
                mMySync.wait(WAIT_MSEC);
            assertTrue(mNetworkInfo.getState() == state);
        }

    }

    private void waitForConnection() throws Exception {
        waitForNetworkInfoState(NetworkInfo.State.CONNECTED);
    }

    private void waitForDisconnection() throws Exception {
        waitForNetworkInfoState(NetworkInfo.State.DISCONNECTED);
    }

    private boolean existSSID(String ssid) {
        for (final WifiConfiguration w : mWifiManager.getConfiguredNetworks()) {
            if (w.SSID.equals(ssid))
                return true;
        }
        return false;
    }

    private int findConfiguredNetworks(String SSID, List<WifiConfiguration> networks) {
        for (final WifiConfiguration w : networks) {
            if (w.SSID.equals(SSID))
                return networks.indexOf(w);
        }
        return -1;
    }

    /**
     * Test creation of WifiManager Lock.
     */
    public void testWifiManagerLock() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        final String TAG = "Test";
        assertNotNull(mWifiManager.createWifiLock(TAG));
        assertNotNull(mWifiManager.createWifiLock(WifiManager.WIFI_MODE_FULL, TAG));
    }

    /**
     * Test wifi scanning when location scan is turned off.
     */
    public void testWifiManagerScanWhenWifiOffLocationTurnedOn() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        if (!hasLocationFeature()) {
            Log.d(TAG, "Skipping test as location is not supported");
            return;
        }
        if (!isLocationEnabled()) {
            fail("Please enable location for this test - since Marshmallow WiFi scan results are"
                    + " empty when location is disabled!");
        }
        setWifiEnabled(false);
        Thread.sleep(DURATION);
        startScan();
        if (mWifiManager.isScanAlwaysAvailable() && isScanCurrentlyAvailable()) {
            // Make sure at least one AP is found.
            assertNotNull("mScanResult should not be null!", mScanResults);
            assertFalse("empty scan results!", mScanResults.isEmpty());
        } else {
            // Make sure no scan results are available.
            assertNull("mScanResult should be null!", mScanResults);
        }
        final String TAG = "Test";
        assertNotNull(mWifiManager.createWifiLock(TAG));
        assertNotNull(mWifiManager.createWifiLock(WifiManager.WIFI_MODE_FULL, TAG));
    }

    /**
     * test point of wifiManager properties:
     * 1.enable properties
     * 2.DhcpInfo properties
     * 3.wifi state
     * 4.ConnectionInfo
     */
    public void testWifiManagerProperties() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        setWifiEnabled(true);
        assertTrue(mWifiManager.isWifiEnabled());
        assertNotNull(mWifiManager.getDhcpInfo());
        assertEquals(WifiManager.WIFI_STATE_ENABLED, mWifiManager.getWifiState());
        mWifiManager.getConnectionInfo();
        setWifiEnabled(false);
        assertFalse(mWifiManager.isWifiEnabled());
    }

    /**
     * Test WiFi scan timestamp - fails when WiFi scan timestamps are inconsistent with
     * {@link SystemClock#elapsedRealtime()} on device.<p>
     * To run this test in cts-tradefed:
     * run cts --class android.net.wifi.cts.WifiManagerTest --method testWifiScanTimestamp
     */
    public void testWifiScanTimestamp() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            Log.d(TAG, "Skipping test as WiFi is not supported");
            return;
        }
        if (!hasLocationFeature()) {
            Log.d(TAG, "Skipping test as location is not supported");
            return;
        }
        if (!isLocationEnabled()) {
            fail("Please enable location for this test - since Marshmallow WiFi scan results are"
                    + " empty when location is disabled!");
        }
        if (!mWifiManager.isWifiEnabled()) {
            setWifiEnabled(true);
        }
        // Scan multiple times to make sure scan timestamps increase with device timestamp.
        for (int i = 0; i < WIFI_SCAN_TEST_ITERATIONS; ++i) {
            startScan();
            // Make sure at least one AP is found.
            assertTrue("mScanResult should not be null. This may be due to a scan timeout",
                       mScanResults != null);
            assertFalse("empty scan results!", mScanResults.isEmpty());
            long nowMillis = SystemClock.elapsedRealtime();
            // Keep track of how many APs are fresh in one scan.
            int numFreshAps = 0;
            for (ScanResult result : mScanResults) {
                long scanTimeMillis = TimeUnit.MICROSECONDS.toMillis(result.timestamp);
                if (Math.abs(nowMillis - scanTimeMillis)  < WIFI_SCAN_TEST_CACHE_DELAY_MILLIS) {
                    numFreshAps++;
                }
            }
            // At least half of the APs in the scan should be fresh.
            int numTotalAps = mScanResults.size();
            String msg = "Stale AP count: " + (numTotalAps - numFreshAps) + ", fresh AP count: "
                    + numFreshAps;
            assertTrue(msg, numFreshAps * 2 >= mScanResults.size());
            if (i < WIFI_SCAN_TEST_ITERATIONS - 1) {
                // Wait before running next iteration.
                Thread.sleep(WIFI_SCAN_TEST_INTERVAL_MILLIS);
            }
        }
    }

    // Return true if location is enabled.
    private boolean isLocationEnabled() {
        return Settings.Secure.getInt(getContext().getContentResolver(),
                Settings.Secure.LOCATION_MODE, Settings.Secure.LOCATION_MODE_OFF) !=
                Settings.Secure.LOCATION_MODE_OFF;
    }

    // Returns true if the device has location feature.
    private boolean hasLocationFeature() {
        return getContext().getPackageManager().hasSystemFeature(PackageManager.FEATURE_LOCATION);
    }

    private boolean hasAutomotiveFeature() {
        return getContext().getPackageManager().hasSystemFeature(PackageManager.FEATURE_AUTOMOTIVE);
    }

    public void testSignal() {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        final int numLevels = 9;
        int expectLevel = 0;
        assertEquals(expectLevel, WifiManager.calculateSignalLevel(MIN_RSSI, numLevels));
        assertEquals(numLevels - 1, WifiManager.calculateSignalLevel(MAX_RSSI, numLevels));
        expectLevel = 4;
        assertEquals(expectLevel, WifiManager.calculateSignalLevel((MIN_RSSI + MAX_RSSI) / 2,
                numLevels));
        int rssiA = 4;
        int rssiB = 5;
        assertTrue(WifiManager.compareSignalLevel(rssiA, rssiB) < 0);
        rssiB = 4;
        assertTrue(WifiManager.compareSignalLevel(rssiA, rssiB) == 0);
        rssiA = 5;
        rssiB = 4;
        assertTrue(WifiManager.compareSignalLevel(rssiA, rssiB) > 0);
    }

    /**
     * Test that {@link WifiManager#calculateSignalLevel(int)} returns a value in the range
     * [0, {@link WifiManager#getMaxSignalLevel()}], and its value is monotonically increasing as
     * the RSSI increases.
     */
    public void testCalculateSignalLevel() {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }

        int maxSignalLevel = mWifiManager.getMaxSignalLevel();

        int prevSignalLevel = 0;
        for (int rssi = -150; rssi <= 50; rssi++) {
            int signalLevel = mWifiManager.calculateSignalLevel(rssi);

            // between [0, maxSignalLevel]
            assertWithMessage("For RSSI=%s", rssi).that(signalLevel).isAtLeast(0);
            assertWithMessage("For RSSI=%s", rssi).that(signalLevel).isAtMost(maxSignalLevel);

            // calculateSignalLevel(rssi) <= calculateSignalLevel(rssi + 1)
            assertWithMessage("For RSSI=%s", rssi).that(signalLevel).isAtLeast(prevSignalLevel);
            prevSignalLevel = signalLevel;
        }
    }

    private static class TestLocalOnlyHotspotCallback extends WifiManager.LocalOnlyHotspotCallback {
        Object hotspotLock;
        WifiManager.LocalOnlyHotspotReservation reservation = null;
        boolean onStartedCalled = false;
        boolean onStoppedCalled = false;
        boolean onFailedCalled = false;
        int failureReason = -1;

        TestLocalOnlyHotspotCallback(Object lock) {
            hotspotLock = lock;
        }

        @Override
        public void onStarted(WifiManager.LocalOnlyHotspotReservation r) {
            synchronized (hotspotLock) {
                reservation = r;
                onStartedCalled = true;
                hotspotLock.notify();
            }
        }

        @Override
        public void onStopped() {
            synchronized (hotspotLock) {
                onStoppedCalled = true;
                hotspotLock.notify();
            }
        }

        @Override
        public void onFailed(int reason) {
            synchronized (hotspotLock) {
                onFailedCalled = true;
                failureReason = reason;
                hotspotLock.notify();
            }
        }
    }

    private TestLocalOnlyHotspotCallback startLocalOnlyHotspot() {
        // Location mode must be enabled for this test
        if (!isLocationEnabled()) {
            fail("Please enable location for this test");
        }

        TestLocalOnlyHotspotCallback callback = new TestLocalOnlyHotspotCallback(mLock);
        synchronized (mLock) {
            try {
                mWifiManager.startLocalOnlyHotspot(callback, null);
                // now wait for callback
                mLock.wait(DURATION);
            } catch (InterruptedException e) {
            }
            // check if we got the callback
            assertTrue(callback.onStartedCalled);
            assertNotNull(callback.reservation.getSoftApConfiguration());
            if (!hasAutomotiveFeature()) {
                assertEquals(
                        SoftApConfiguration.BAND_2GHZ,
                        callback.reservation.getSoftApConfiguration().getBand());
            }
            assertFalse(callback.onFailedCalled);
            assertFalse(callback.onStoppedCalled);
        }
        return callback;
    }

    private void stopLocalOnlyHotspot(TestLocalOnlyHotspotCallback callback, boolean wifiEnabled) {
       synchronized (mMySync) {
           // we are expecting a new state
           mMySync.expectedState = STATE_WIFI_CHANGING;

           // now shut down LocalOnlyHotspot
           callback.reservation.close();

           try {
               waitForExpectedWifiState(wifiEnabled);
           } catch (InterruptedException e) {}
        }
    }

    /**
     * Verify that calls to startLocalOnlyHotspot succeed with proper permissions.
     *
     * Note: Location mode must be enabled for this test.
     */
    public void testStartLocalOnlyHotspotSuccess() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        // check that softap mode is supported by the device
        if (!mWifiManager.isPortableHotspotSupported()) {
            return;
        }

        boolean wifiEnabled = mWifiManager.isWifiEnabled();

        TestLocalOnlyHotspotCallback callback = startLocalOnlyHotspot();

        // add sleep to avoid calling stopLocalOnlyHotspot before TetherController initialization.
        // TODO: remove this sleep as soon as b/124330089 is fixed.
        Log.d(TAG, "Sleeping for 2 seconds");
        Thread.sleep(2000);

        stopLocalOnlyHotspot(callback, wifiEnabled);

        // wifi should either stay on, or come back on
        assertEquals(wifiEnabled, mWifiManager.isWifiEnabled());
    }

    /**
     * Verify calls to deprecated API's all fail for non-settings apps targeting >= Q SDK.
     */
    public void testDeprecatedApis() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        setWifiEnabled(true);
        waitForConnection(); // ensures that there is at-least 1 saved network on the device.

        WifiConfiguration wifiConfiguration = new WifiConfiguration();
        wifiConfiguration.SSID = SSID1;
        wifiConfiguration.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);

        assertEquals(INVALID_NETWORK_ID,
                mWifiManager.addNetwork(wifiConfiguration));
        assertEquals(INVALID_NETWORK_ID,
                mWifiManager.updateNetwork(wifiConfiguration));
        assertFalse(mWifiManager.enableNetwork(0, true));
        assertFalse(mWifiManager.disableNetwork(0));
        assertFalse(mWifiManager.removeNetwork(0));
        assertFalse(mWifiManager.disconnect());
        assertFalse(mWifiManager.reconnect());
        assertFalse(mWifiManager.reassociate());
        assertTrue(mWifiManager.getConfiguredNetworks().isEmpty());

        boolean wifiEnabled = mWifiManager.isWifiEnabled();
        // now we should fail to toggle wifi state.
        assertFalse(mWifiManager.setWifiEnabled(!wifiEnabled));
        Thread.sleep(DURATION);
        assertEquals(wifiEnabled, mWifiManager.isWifiEnabled());
    }

    /**
     * Verify that applications can only have one registered LocalOnlyHotspot request at a time.
     *
     * Note: Location mode must be enabled for this test.
     */
    public void testStartLocalOnlyHotspotSingleRequestByApps() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        // check that softap mode is supported by the device
        if (!mWifiManager.isPortableHotspotSupported()) {
            return;
        }

        boolean caughtException = false;

        boolean wifiEnabled = mWifiManager.isWifiEnabled();

        TestLocalOnlyHotspotCallback callback = startLocalOnlyHotspot();

        // now make a second request - this should fail.
        TestLocalOnlyHotspotCallback callback2 = new TestLocalOnlyHotspotCallback(mLock);
        try {
            mWifiManager.startLocalOnlyHotspot(callback2, null);
        } catch (IllegalStateException e) {
            Log.d(TAG, "Caught the IllegalStateException we expected: called startLOHS twice");
            caughtException = true;
        }
        if (!caughtException) {
            // second start did not fail, should clean up the hotspot.

            // add sleep to avoid calling stopLocalOnlyHotspot before TetherController initialization.
            // TODO: remove this sleep as soon as b/124330089 is fixed.
            Log.d(TAG, "Sleeping for 2 seconds");
            Thread.sleep(2000);

            stopLocalOnlyHotspot(callback2, wifiEnabled);
        }
        assertTrue(caughtException);

        // add sleep to avoid calling stopLocalOnlyHotspot before TetherController initialization.
        // TODO: remove this sleep as soon as b/124330089 is fixed.
        Log.d(TAG, "Sleeping for 2 seconds");
        Thread.sleep(2000);

        stopLocalOnlyHotspot(callback, wifiEnabled);
    }

    private static class TestExecutor implements Executor {
        private ConcurrentLinkedQueue<Runnable> tasks = new ConcurrentLinkedQueue<>();

        @Override
        public void execute(Runnable task) {
            tasks.add(task);
        }

        private void runAll() {
            Runnable task = tasks.poll();
            while (task != null) {
                task.run();
                task = tasks.poll();
            }
        }
    }

    public void testStartLocalOnlyHotspotWithConfig() throws Exception {
        SoftApConfiguration customConfig = new SoftApConfiguration.Builder()
                .setBssid(TEST_MAC)
                .setSsid(TEST_SSID_UNQUOTED)
                .setPassphrase(TEST_PASSPHRASE, SoftApConfiguration.SECURITY_TYPE_WPA2_PSK)
                .build();
        TestExecutor executor = new TestExecutor();
        TestLocalOnlyHotspotCallback callback = new TestLocalOnlyHotspotCallback(mLock);
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        try {
            uiAutomation.adoptShellPermissionIdentity();

            boolean wifiEnabled = mWifiManager.isWifiEnabled();
            mWifiManager.startLocalOnlyHotspot(customConfig, executor, callback);
            Log.d(TAG, "Sleeping for 2 seconds");
            Thread.sleep(2000);

            // Verify callback is run on the supplied executor
            assertFalse(callback.onStartedCalled);
            executor.runAll();
            assertTrue(callback.onStartedCalled);

            assertNotNull(callback.reservation);
            SoftApConfiguration softApConfig = callback.reservation.getSoftApConfiguration();
            assertNotNull(softApConfig);
            assertEquals(TEST_MAC, softApConfig.getBssid());
            assertEquals(TEST_SSID_UNQUOTED, softApConfig.getSsid());
            assertEquals(TEST_PASSPHRASE, softApConfig.getPassphrase());

            // clean up
            stopLocalOnlyHotspot(callback, wifiEnabled);
        } finally {
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Read the content of the given resource file into a String.
     *
     * @param filename String name of the file
     * @return String
     * @throws IOException
     */
    private String loadResourceFile(String filename) throws IOException {
        InputStream in = getClass().getClassLoader().getResourceAsStream(filename);
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        StringBuilder builder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            builder.append(line).append("\n");
        }
        return builder.toString();
    }

    /**
     * Verify that changing the mac randomization setting of a Passpoint configuration.
     */
    public void testMacRandomizationSettingPasspoint() throws Exception {
        String configStr = loadResourceFile(PASSPOINT_INSTALLATION_FILE_WITH_CA_CERT);
        PasspointConfiguration config =
                ConfigParser.parsePasspointConfig(TYPE_WIFI_CONFIG, configStr.getBytes());
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        try {
            uiAutomation.adoptShellPermissionIdentity();

            mWifiManager.addOrUpdatePasspointConfiguration(config);
            List<PasspointConfiguration> passpointConfigs =
                    mWifiManager.getPasspointConfigurations();
            PasspointConfiguration passpointConfig = passpointConfigs.get(0);
            assertEquals(1, passpointConfigs.size());
            assertTrue("Mac randomization should be enabled for passpoint networks by default.",
                    passpointConfig.isMacRandomizationEnabled());

            String fqdn = passpointConfig.getHomeSp().getFqdn();
            mWifiManager.setMacRandomizationSettingPasspointEnabled(fqdn, false);
            assertFalse("Mac randomization should be disabled by the API call.",
                    mWifiManager.getPasspointConfigurations().get(0).isMacRandomizationEnabled());
        } finally {
            uiAutomation.dropShellPermissionIdentity();
        }
    }
    /**
     * Verify that the {@link android.Manifest.permission#NETWORK_STACK} permission is never held by
     * any package.
     * <p>
     * No apps should <em>ever</em> attempt to acquire this permission, since it would give those
     * apps extremely broad access to connectivity functionality.
     */
    public void testNetworkStackPermission() {
        final PackageManager pm = getContext().getPackageManager();

        final List<PackageInfo> holding = pm.getPackagesHoldingPermissions(new String[] {
                android.Manifest.permission.NETWORK_STACK
        }, PackageManager.MATCH_UNINSTALLED_PACKAGES);
        for (PackageInfo pi : holding) {
            fail("The NETWORK_STACK permission must not be held by " + pi.packageName
                    + " and must be revoked for security reasons");
        }
    }

    /**
     * Verify that the {@link android.Manifest.permission#NETWORK_SETTINGS} permission is
     * never held by any package.
     * <p>
     * Only Settings, SysUi, NetworkStack and shell apps should <em>ever</em> attempt to acquire
     * this permission, since it would give those apps extremely broad access to connectivity
     * functionality.  The permission is intended to be granted to only those apps with direct user
     * access and no others.
     */
    public void testNetworkSettingsPermission() {
        final PackageManager pm = getContext().getPackageManager();

        final ArraySet<String> allowedPackages = new ArraySet();
        final ArraySet<Integer> allowedUIDs = new ArraySet();
        // explicitly add allowed UIDs
        allowedUIDs.add(Process.SYSTEM_UID);
        allowedUIDs.add(Process.SHELL_UID);
        allowedUIDs.add(Process.PHONE_UID);
        allowedUIDs.add(Process.NETWORK_STACK_UID);
        allowedUIDs.add(Process.NFC_UID);

        // only quick settings is allowed to bind to the BIND_QUICK_SETTINGS_TILE permission, using
        // this fact to determined allowed package name for sysui. This is a signature permission,
        // so allow any package with this permission.
        final List<PackageInfo> sysuiPackages = pm.getPackagesHoldingPermissions(new String[] {
                android.Manifest.permission.BIND_QUICK_SETTINGS_TILE
        }, PackageManager.MATCH_UNINSTALLED_PACKAGES);
        for (PackageInfo info : sysuiPackages) {
            allowedPackages.add(info.packageName);
        }

        // the captive portal flow also currently holds the NETWORK_SETTINGS permission
        final Intent intent = new Intent(ConnectivityManager.ACTION_CAPTIVE_PORTAL_SIGN_IN);
        final ResolveInfo ri = pm.resolveActivity(intent, PackageManager.MATCH_DISABLED_COMPONENTS);
        if (ri != null) {
            allowedPackages.add(ri.activityInfo.packageName);
        }

        final List<PackageInfo> holding = pm.getPackagesHoldingPermissions(new String[] {
                android.Manifest.permission.NETWORK_SETTINGS
        }, PackageManager.MATCH_UNINSTALLED_PACKAGES);
        StringBuilder stringBuilder = new StringBuilder();
        for (PackageInfo pi : holding) {
            String packageName = pi.packageName;

            // this is an explicitly allowed package
            if (allowedPackages.contains(packageName)) continue;

            // now check if the packages are from allowed UIDs
            int uid = -1;
            try {
                uid = pm.getPackageUidAsUser(packageName, UserHandle.USER_SYSTEM);
            } catch (PackageManager.NameNotFoundException e) {
                continue;
            }
            if (!allowedUIDs.contains(uid)) {
                stringBuilder.append("The NETWORK_SETTINGS permission must not be held by "
                    + packageName + ":" + uid + " and must be revoked for security reasons\n");
            }
        }
        if (stringBuilder.length() > 0) {
            fail(stringBuilder.toString());
        }
    }

    /**
     * Verify that the {@link android.Manifest.permission#NETWORK_SETUP_WIZARD} permission is
     * only held by the device setup wizard application.
     * <p>
     * Only the SetupWizard app should <em>ever</em> attempt to acquire this
     * permission, since it would give those apps extremely broad access to connectivity
     * functionality.  The permission is intended to be granted to only the device setup wizard.
     */
    public void testNetworkSetupWizardPermission() {
        final ArraySet<String> allowedPackages = new ArraySet();

        final PackageManager pm = getContext().getPackageManager();

        final Intent intent = new Intent(Intent.ACTION_MAIN);
        intent.addCategory(Intent.CATEGORY_SETUP_WIZARD);
        final ResolveInfo ri = pm.resolveActivity(intent, PackageManager.MATCH_DISABLED_COMPONENTS);
        String validPkg = "";
        if (ri != null) {
            allowedPackages.add(ri.activityInfo.packageName);
            validPkg = ri.activityInfo.packageName;
        }

        final Intent preIntent = new Intent("com.android.setupwizard.OEM_PRE_SETUP");
        preIntent.addCategory(Intent.CATEGORY_DEFAULT);
        final ResolveInfo preRi = pm
            .resolveActivity(preIntent, PackageManager.MATCH_DISABLED_COMPONENTS);
        String prePackageName = "";
        if (null != preRi) {
            prePackageName = preRi.activityInfo.packageName;
        }

        final Intent postIntent = new Intent("com.android.setupwizard.OEM_POST_SETUP");
        postIntent.addCategory(Intent.CATEGORY_DEFAULT);
        final ResolveInfo postRi = pm
            .resolveActivity(postIntent, PackageManager.MATCH_DISABLED_COMPONENTS);
        String postPackageName = "";
        if (null != postRi) {
            postPackageName = postRi.activityInfo.packageName;
        }
        if (!TextUtils.isEmpty(prePackageName) && !TextUtils.isEmpty(postPackageName)
            && prePackageName.equals(postPackageName)) {
            allowedPackages.add(prePackageName);
        }

        final List<PackageInfo> holding = pm.getPackagesHoldingPermissions(new String[]{
            android.Manifest.permission.NETWORK_SETUP_WIZARD
        }, PackageManager.MATCH_UNINSTALLED_PACKAGES);
        for (PackageInfo pi : holding) {
            if (!allowedPackages.contains(pi.packageName)) {
                fail("The NETWORK_SETUP_WIZARD permission must not be held by " + pi.packageName
                    + " and must be revoked for security reasons [" + validPkg + "]");
            }
        }
    }

    /**
     * Verify that the {@link android.Manifest.permission#NETWORK_MANAGED_PROVISIONING} permission
     * is only held by the device managed provisioning application.
     * <p>
     * Only the ManagedProvisioning app should <em>ever</em> attempt to acquire this
     * permission, since it would give those apps extremely broad access to connectivity
     * functionality.  The permission is intended to be granted to only the device managed
     * provisioning.
     */
    public void testNetworkManagedProvisioningPermission() {
        final PackageManager pm = getContext().getPackageManager();

        // TODO(b/115980767): Using hardcoded package name. Need a better mechanism to find the
        // managed provisioning app.
        // Ensure that the package exists.
        final Intent intent = new Intent(Intent.ACTION_MAIN);
        intent.setPackage(MANAGED_PROVISIONING_PACKAGE_NAME);
        final ResolveInfo ri = pm.resolveActivity(intent, PackageManager.MATCH_DISABLED_COMPONENTS);
        String validPkg = "";
        if (ri != null) {
            validPkg = ri.activityInfo.packageName;
        }

        final List<PackageInfo> holding = pm.getPackagesHoldingPermissions(new String[] {
                android.Manifest.permission.NETWORK_MANAGED_PROVISIONING
        }, PackageManager.MATCH_UNINSTALLED_PACKAGES);
        for (PackageInfo pi : holding) {
            if (!Objects.equals(pi.packageName, validPkg)) {
                fail("The NETWORK_MANAGED_PROVISIONING permission must not be held by "
                        + pi.packageName + " and must be revoked for security reasons ["
                        + validPkg +"]");
            }
        }
    }

    /**
     * Verify that the {@link android.Manifest.permission#WIFI_SET_DEVICE_MOBILITY_STATE} permission
     * is held by at most one application.
     */
    public void testWifiSetDeviceMobilityStatePermission() {
        final PackageManager pm = getContext().getPackageManager();

        final List<PackageInfo> holding = pm.getPackagesHoldingPermissions(new String[] {
                android.Manifest.permission.WIFI_SET_DEVICE_MOBILITY_STATE
        }, PackageManager.MATCH_UNINSTALLED_PACKAGES);

        List<String> uniquePackageNames = holding
                .stream()
                .map(pi -> pi.packageName)
                .distinct()
                .collect(Collectors.toList());

        if (uniquePackageNames.size() > 1) {
            fail("The WIFI_SET_DEVICE_MOBILITY_STATE permission must not be held by more than one "
                    + "application, but is held by " + uniquePackageNames.size() + " applications: "
                    + String.join(", ", uniquePackageNames));
        }
    }

    /**
     * Verify that the {@link android.Manifest.permission#NETWORK_CARRIER_PROVISIONING} permission
     * is held by at most one application.
     */
    public void testNetworkCarrierProvisioningPermission() {
        final PackageManager pm = getContext().getPackageManager();

        final List<PackageInfo> holding = pm.getPackagesHoldingPermissions(new String[] {
                android.Manifest.permission.NETWORK_CARRIER_PROVISIONING
        }, PackageManager.MATCH_UNINSTALLED_PACKAGES);

        List<String> uniquePackageNames = holding
                .stream()
                .map(pi -> pi.packageName)
                .distinct()
                .collect(Collectors.toList());

        if (uniquePackageNames.size() > 2) {
            fail("The NETWORK_CARRIER_PROVISIONING permission must not be held by more than two "
                    + "applications, but is held by " + uniquePackageNames.size() + " applications: "
                    + String.join(", ", uniquePackageNames));
        }
    }

    /**
     * Verify that the {@link android.Manifest.permission#WIFI_UPDATE_USABILITY_STATS_SCORE}
     * permission is held by at most one application.
     */
    public void testUpdateWifiUsabilityStatsScorePermission() {
        final PackageManager pm = getContext().getPackageManager();

        final List<PackageInfo> holding = pm.getPackagesHoldingPermissions(new String[] {
                android.Manifest.permission.WIFI_UPDATE_USABILITY_STATS_SCORE
        }, PackageManager.MATCH_UNINSTALLED_PACKAGES);

        List<String> uniquePackageNames = holding
                .stream()
                .map(pi -> pi.packageName)
                .distinct()
                .collect(Collectors.toList());

        if (uniquePackageNames.size() > 1) {
            fail("The WIFI_UPDATE_USABILITY_STATS_SCORE permission must not be held by more than "
                + "one application, but is held by " + uniquePackageNames.size() + " applications: "
                + String.join(", ", uniquePackageNames));
        }
    }

    private void turnScreenOnNoDelay() throws Exception {
        mUiDevice.executeShellCommand("input keyevent KEYCODE_WAKEUP");
        mUiDevice.executeShellCommand("wm dismiss-keyguard");
    }

    private void turnScreenOn() throws Exception {
        turnScreenOnNoDelay();
        // Since the screen on/off intent is ordered, they will not be sent right now.
        Thread.sleep(DURATION_SCREEN_TOGGLE);
    }

    private void turnScreenOff() throws Exception {
        mUiDevice.executeShellCommand("input keyevent KEYCODE_SLEEP");
        // Since the screen on/off intent is ordered, they will not be sent right now.
        Thread.sleep(DURATION_SCREEN_TOGGLE);
    }

    private void assertWifiScanningIsOn() {
        if (!mWifiManager.isScanAlwaysAvailable()) {
            fail("Wi-Fi scanning should be on.");
        }
    }

    private void runWithScanningEnabled(ThrowingRunnable r) throws Exception {
        boolean wasScanEnabledForTest = false;
        if (!mWifiManager.isScanAlwaysAvailable()) {
            ShellIdentityUtils.invokeWithShellPermissions(
                    () -> mWifiManager.setScanAlwaysAvailable(true));
            wasScanEnabledForTest = true;
        }
        try {
            r.run();
        } finally {
            if (wasScanEnabledForTest) {
                ShellIdentityUtils.invokeWithShellPermissions(
                        () -> mWifiManager.setScanAlwaysAvailable(false));
            }
        }
    }

    /**
     * Verify that Wi-Fi scanning is not turned off when the screen turns off while wifi is disabled
     * but location is on.
     * @throws Exception
     */
    public void testScreenOffDoesNotTurnOffWifiScanningWhenWifiDisabled() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        if (!hasLocationFeature()) {
            // skip the test if location is not supported
            return;
        }
        if (!isLocationEnabled()) {
            fail("Please enable location for this test - since Marshmallow WiFi scan results are"
                    + " empty when location is disabled!");
        }
        runWithScanningEnabled(() -> {
            setWifiEnabled(false);
            turnScreenOn();
            assertWifiScanningIsOn();
            // Toggle screen and verify Wi-Fi scanning is still on.
            turnScreenOff();
            assertWifiScanningIsOn();
            turnScreenOn();
            assertWifiScanningIsOn();
        });
    }

    /**
     * Verify that Wi-Fi scanning is not turned off when the screen turns off while wifi is enabled.
     * @throws Exception
     */
    public void testScreenOffDoesNotTurnOffWifiScanningWhenWifiEnabled() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        if (!hasLocationFeature()) {
            // skip the test if location is not supported
            return;
        }
        if (!isLocationEnabled()) {
            fail("Please enable location for this test - since Marshmallow WiFi scan results are"
                    + " empty when location is disabled!");
        }
        runWithScanningEnabled(() -> {
            setWifiEnabled(true);
            turnScreenOn();
            assertWifiScanningIsOn();
            // Toggle screen and verify Wi-Fi scanning is still on.
            turnScreenOff();
            assertWifiScanningIsOn();
            turnScreenOn();
            assertWifiScanningIsOn();
        });
    }

    /**
     * Verify that the platform supports a reasonable number of suggestions per app.
     * @throws Exception
     */
    public void testMaxNumberOfNetworkSuggestionsPerApp() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        assertTrue(mWifiManager.getMaxNumberOfNetworkSuggestionsPerApp()
                > ENFORCED_NUM_NETWORK_SUGGESTIONS_PER_APP);
    }

    private static class TestActionListener implements WifiManager.ActionListener {
        private final Object mLock;
        public boolean onSuccessCalled = false;
        public boolean onFailedCalled = false;
        public int failureReason = -1;

        TestActionListener(Object lock) {
            mLock = lock;
        }

        @Override
        public void onSuccess() {
            synchronized (mLock) {
                onSuccessCalled = true;
                mLock.notify();
            }
        }

        @Override
        public void onFailure(int reason) {
            synchronized (mLock) {
                onFailedCalled = true;
                failureReason = reason;
                mLock.notify();
            }
        }
    }

    /**
     * Triggers connection to one of the saved networks using {@link WifiManager#connect(
     * int, WifiManager.ActionListener)} or {@link WifiManager#connect(WifiConfiguration,
     * WifiManager.ActionListener)}
     *
     * @param withNetworkId Use networkId for triggering connection, false for using
     *                      WifiConfiguration.
     * @throws Exception
     */
    private void testConnect(boolean withNetworkId) throws Exception {
        TestActionListener actionListener = new TestActionListener(mLock);
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        List<WifiConfiguration> savedNetworks = null;
        try {
            uiAutomation.adoptShellPermissionIdentity();
            // These below API's only work with privileged permissions (obtained via shell identity
            // for test)
            savedNetworks = mWifiManager.getConfiguredNetworks();

            // Disable all the saved networks to trigger disconnect & disable autojoin.
            for (WifiConfiguration network : savedNetworks) {
                assertTrue(mWifiManager.disableNetwork(network.networkId));
            }
            waitForDisconnection();

            // Now trigger connection to the first saved network.
            synchronized (mLock) {
                try {
                    if (withNetworkId) {
                        mWifiManager.connect(savedNetworks.get(0).networkId, actionListener);
                    } else {
                        mWifiManager.connect(savedNetworks.get(0), actionListener);
                    }
                    // now wait for callback
                    mLock.wait(DURATION);
                } catch (InterruptedException e) {
                }
            }
            // check if we got the success callback
            assertTrue(actionListener.onSuccessCalled);
            // Wait for connection to complete & ensure we are connected to the saved network.
            waitForConnection();
            assertEquals(savedNetworks.get(0).networkId,
                    mWifiManager.getConnectionInfo().getNetworkId());
        } finally {
            // Re-enable all saved networks before exiting.
            if (savedNetworks != null) {
                for (WifiConfiguration network : savedNetworks) {
                    mWifiManager.enableNetwork(network.networkId, false);
                }
            }
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests {@link WifiManager#connect(int, WifiManager.ActionListener)} to an existing saved
     * network.
     */
    public void testConnectWithNetworkId() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        testConnect(true);
    }

    /**
     * Tests {@link WifiManager#connect(WifiConfiguration, WifiManager.ActionListener)} to an
     * existing saved network.
     */
    public void testConnectWithWifiConfiguration() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        testConnect(false);

    }

    private static class TestNetworkCallback extends ConnectivityManager.NetworkCallback {
        private final Object mLock;
        public boolean onAvailableCalled = false;
        public Network network;
        public NetworkCapabilities networkCapabilities;

        TestNetworkCallback(Object lock) {
            mLock = lock;
        }

        @Override
        public void onAvailable(Network network, NetworkCapabilities networkCapabilities,
                LinkProperties linkProperties, boolean blocked) {
            synchronized (mLock) {
                onAvailableCalled = true;
                this.network = network;
                this.networkCapabilities = networkCapabilities;
                mLock.notify();
            }
        }
    }

    private void waitForNetworkCallbackAndCheckForMeteredness(boolean expectMetered) {
        TestNetworkCallback networkCallbackListener = new TestNetworkCallback(mLock);
        synchronized (mLock) {
            try {
                // File a request for wifi network.
                mConnectivityManager.registerNetworkCallback(
                        new NetworkRequest.Builder()
                                .addTransportType(TRANSPORT_WIFI)
                                .build(),
                        networkCallbackListener);
                // now wait for callback
                mLock.wait(DURATION);
            } catch (InterruptedException e) {
            }
        }
        assertTrue(networkCallbackListener.onAvailableCalled);
        assertNotEquals(expectMetered, networkCallbackListener.networkCapabilities.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_NOT_METERED));
    }

    /**
     * Tests {@link WifiManager#save(WifiConfiguration, WifiManager.ActionListener)} by marking
     * an existing saved network metered.
     */
    public void testSave() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        TestActionListener actionListener = new TestActionListener(mLock);
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        List<WifiConfiguration> savedNetworks = null;
        WifiConfiguration savedNetwork = null;
        try {
            uiAutomation.adoptShellPermissionIdentity();
            // These below API's only work with privileged permissions (obtained via shell identity
            // for test)
            savedNetworks = mWifiManager.getConfiguredNetworks();

            // Ensure that the saved network is not metered.
            savedNetwork = savedNetworks.get(0);
            assertNotEquals("Ensure that the saved network is configured as unmetered",
                    savedNetwork.meteredOverride,
                    WifiConfiguration.METERED_OVERRIDE_METERED);

            // Trigger a scan & wait for connection to one of the saved networks.
            mWifiManager.startScan();
            waitForConnection();

            // Check the network capabilities to ensure that the network is marked not metered.
            waitForNetworkCallbackAndCheckForMeteredness(false);

            // Now mark the network metered and save.
            synchronized (mLock) {
                try {
                    WifiConfiguration modSavedNetwork = new WifiConfiguration(savedNetwork);
                    modSavedNetwork.meteredOverride = WifiConfiguration.METERED_OVERRIDE_METERED;
                    mWifiManager.save(modSavedNetwork, actionListener);
                    // now wait for callback
                    mLock.wait(DURATION);
                } catch (InterruptedException e) {
                }
            }
            // check if we got the success callback
            assertTrue(actionListener.onSuccessCalled);
            // Check the network capabilities to ensure that the network is marked metered now.
            waitForNetworkCallbackAndCheckForMeteredness(true);

        } finally {
            // Restore original network config (restore the meteredness back);
            if (savedNetwork != null) {
                mWifiManager.updateNetwork(savedNetwork);
            }
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests {@link WifiManager#forget(int, WifiManager.ActionListener)} by adding/removing a new
     * network.
     */
    public void testForget() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        TestActionListener actionListener = new TestActionListener(mLock);
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        int newNetworkId = INVALID_NETWORK_ID;
        try {
            uiAutomation.adoptShellPermissionIdentity();
            // These below API's only work with privileged permissions (obtained via shell identity
            // for test)
            List<WifiConfiguration> savedNetworks = mWifiManager.getConfiguredNetworks();

            WifiConfiguration newOpenNetwork = new WifiConfiguration();
            newOpenNetwork.SSID = "\"" + TEST_SSID_UNQUOTED + "\"";
            newNetworkId = mWifiManager.addNetwork(newOpenNetwork);
            assertNotEquals(INVALID_NETWORK_ID, newNetworkId);

            assertEquals(savedNetworks.size() + 1, mWifiManager.getConfiguredNetworks().size());

            // Now remove the network
            synchronized (mLock) {
                try {
                    mWifiManager.forget(newNetworkId, actionListener);
                    // now wait for callback
                    mLock.wait(DURATION);
                } catch (InterruptedException e) {
                }
            }
            // check if we got the success callback
            assertTrue(actionListener.onSuccessCalled);

            // Ensure that the new network has been successfully removed.
            assertEquals(savedNetworks.size(), mWifiManager.getConfiguredNetworks().size());
        } finally {
            // For whatever reason, if the forget fails, try removing using the public remove API.
            if (newNetworkId != INVALID_NETWORK_ID) mWifiManager.removeNetwork(newNetworkId);
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests {@link WifiManager#getFactoryMacAddresses()} returns at least one valid MAC address.
     */
    public void testGetFactoryMacAddresses() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        TestActionListener actionListener = new TestActionListener(mLock);
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        int newNetworkId = INVALID_NETWORK_ID;
        try {
            uiAutomation.adoptShellPermissionIdentity();
            // Obtain the factory MAC address
            String[] macAddresses = mWifiManager.getFactoryMacAddresses();
            assertTrue("At list one MAC address should be returned.", macAddresses.length > 0);
            try {
                MacAddress mac = MacAddress.fromString(macAddresses[0]);
                assertNotEquals(WifiInfo.DEFAULT_MAC_ADDRESS, mac);
                assertFalse(MacAddressUtils.isMulticastAddress(mac));
            } catch (IllegalArgumentException e) {
                fail("Factory MAC address is invalid");
            }
        } finally {
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests {@link WifiManager#isApMacRandomizationSupported()} does not crash.
     */
    public void testIsApMacRandomizationSupported() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        mWifiManager.isApMacRandomizationSupported();
    }

    /**
     * Tests {@link WifiManager#isConnectedMacRandomizationSupported()} does not crash.
     */
    public void testIsConnectedMacRandomizationSupported() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        mWifiManager.isConnectedMacRandomizationSupported();
    }

    /**
     * Tests {@link WifiManager#isPreferredNetworkOffloadSupported()} does not crash.
     */
    public void testIsPreferredNetworkOffloadSupported() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        mWifiManager.isPreferredNetworkOffloadSupported();
    }

    /**
     * Tests {@link WifiManager#isTdlsSupported()} does not crash.
     */
    public void testIsTdlsSupported() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        mWifiManager.isTdlsSupported();
    }

    /**
     * Tests {@link WifiManager#isStaApConcurrencySupported().
     */
    public void testIsStaApConcurrencySupported() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        // check that softap mode is supported by the device
        if (!mWifiManager.isPortableHotspotSupported()) {
            return;
        }
        assertTrue(mWifiManager.isWifiEnabled());

        boolean isStaApConcurrencySupported = mWifiManager.isStaApConcurrencySupported();
        // start local only hotspot.
        TestLocalOnlyHotspotCallback callback = startLocalOnlyHotspot();
        if (isStaApConcurrencySupported) {
            assertTrue(mWifiManager.isWifiEnabled());
        } else {
            // no concurrency, wifi should be disabled.
            assertFalse(mWifiManager.isWifiEnabled());
        }
        stopLocalOnlyHotspot(callback, true);

        assertTrue(mWifiManager.isWifiEnabled());
    }

    private static class TestTrafficStateCallback implements WifiManager.TrafficStateCallback {
        private final Object mLock;
        public boolean onStateChangedCalled = false;
        public int state = -1;

        TestTrafficStateCallback(Object lock) {
            mLock = lock;
        }

        @Override
        public void onStateChanged(int state) {
            synchronized (mLock) {
                onStateChangedCalled = true;
                this.state = state;
                mLock.notify();
            }
        }
    }

    private void sendTraffic() {
        for (int i = 0; i < 10; i ++) {
            // Do some network operations
            HttpURLConnection connection = null;
            try {
                URL url = new URL("http://www.google.com/");
                connection = (HttpURLConnection) url.openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(TIMEOUT_MSEC);
                connection.setReadTimeout(TIMEOUT_MSEC);
                connection.setUseCaches(false);
                connection.getInputStream();
            } catch (Exception e) {
                // ignore
            } finally {
                if (connection != null) connection.disconnect();
            }
        }
    }

    /**
     * Tests {@link WifiManager#registerTrafficStateCallback(Executor,
     * WifiManager.TrafficStateCallback)} by sending some traffic.
     */
    public void testTrafficStateCallback() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        TestTrafficStateCallback trafficStateCallback = new TestTrafficStateCallback(mLock);
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        try {
            uiAutomation.adoptShellPermissionIdentity();
            // Trigger a scan & wait for connection to one of the saved networks.
            mWifiManager.startScan();
            waitForConnection();

            // Turn screen on for wifi traffic polling.
            turnScreenOn();
            synchronized (mLock) {
                try {
                    mWifiManager.registerTrafficStateCallback(
                            Executors.newSingleThreadExecutor(), trafficStateCallback);
                    // Send some traffic to trigger the traffic state change callbacks.
                    sendTraffic();
                    // now wait for callback
                    mLock.wait(DURATION);
                } catch (InterruptedException e) {
                }
            }
            // check if we got the state changed callback
            assertTrue(trafficStateCallback.onStateChangedCalled);
            assertEquals(DATA_ACTIVITY_INOUT, trafficStateCallback.state);
        } finally {
            turnScreenOff();
            mWifiManager.unregisterTrafficStateCallback(trafficStateCallback);
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests {@link WifiManager#setScanAlwaysAvailable(boolean)} &
     * {@link WifiManager#isScanAlwaysAvailable()}.
     */
    public void testScanAlwaysAvailable() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        Boolean currState = null;
        try {
            uiAutomation.adoptShellPermissionIdentity();
            currState = mWifiManager.isScanAlwaysAvailable();
            boolean newState = !currState;
            mWifiManager.setScanAlwaysAvailable(newState);
            PollingCheck.check(
                    "Wifi settings toggle failed!",
                    DURATION_SETTINGS_TOGGLE,
                    () -> mWifiManager.isScanAlwaysAvailable() == newState);
            assertEquals(newState, mWifiManager.isScanAlwaysAvailable());
        } finally {
            if (currState != null) mWifiManager.setScanAlwaysAvailable(currState);
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests {@link WifiManager#setScanThrottleEnabled(boolean)} &
     * {@link WifiManager#isScanThrottleEnabled()}.
     */
    public void testScanThrottleEnabled() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        Boolean currState = null;
        try {
            uiAutomation.adoptShellPermissionIdentity();
            currState = mWifiManager.isScanThrottleEnabled();
            boolean newState = !currState;
            mWifiManager.setScanThrottleEnabled(newState);
            PollingCheck.check(
                    "Wifi settings toggle failed!",
                    DURATION_SETTINGS_TOGGLE,
                    () -> mWifiManager.isScanThrottleEnabled() == newState);
            assertEquals(newState, mWifiManager.isScanThrottleEnabled());
        } finally {
            if (currState != null) mWifiManager.setScanThrottleEnabled(currState);
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests {@link WifiManager#setAutoWakeupEnabled(boolean)} &
     * {@link WifiManager#isAutoWakeupEnabled()}.
     */
    public void testAutoWakeUpEnabled() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        Boolean currState = null;
        try {
            uiAutomation.adoptShellPermissionIdentity();
            currState = mWifiManager.isAutoWakeupEnabled();
            boolean newState = !currState;
            mWifiManager.setAutoWakeupEnabled(newState);
            PollingCheck.check(
                    "Wifi settings toggle failed!",
                    DURATION_SETTINGS_TOGGLE,
                    () -> mWifiManager.isAutoWakeupEnabled() == newState);
            assertEquals(newState, mWifiManager.isAutoWakeupEnabled());
        } finally {
            if (currState != null) mWifiManager.setAutoWakeupEnabled(currState);
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests {@link WifiManager#setVerboseLoggingEnabled(boolean)} &
     * {@link WifiManager#isVerboseLoggingEnabled()}.
     */
    public void testVerboseLoggingEnabled() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        Boolean currState = null;
        try {
            uiAutomation.adoptShellPermissionIdentity();
            currState = mWifiManager.isVerboseLoggingEnabled();
            boolean newState = !currState;
            mWifiManager.setVerboseLoggingEnabled(newState);
            PollingCheck.check(
                    "Wifi settings toggle failed!",
                    DURATION_SETTINGS_TOGGLE,
                    () -> mWifiManager.isVerboseLoggingEnabled() == newState);
            assertEquals(newState, mWifiManager.isVerboseLoggingEnabled());
        } finally {
            if (currState != null) mWifiManager.setVerboseLoggingEnabled(currState);
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests {@link WifiManager#factoryReset()}.
     *
     * Note: This test assumes that the device only has 1 or more saved networks before the test.
     * The test will restore those when the test exits. But, it does not restore the softap
     * configuration, suggestions, etc which will also have been lost on factory reset.
     */
    public void testFactoryReset() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        List<WifiConfiguration> savedNetworks = null;
        try {
            uiAutomation.adoptShellPermissionIdentity();
            // These below API's only work with privileged permissions (obtained via shell identity
            // for test)
            savedNetworks = mWifiManager.getConfiguredNetworks();

            mWifiManager.factoryReset();
            // Ensure all the saved networks are removed.
            assertEquals(0, mWifiManager.getConfiguredNetworks().size());
        } finally {
            // Restore the original saved networks.
            if (savedNetworks != null) {
                for (WifiConfiguration network : savedNetworks) {
                    mWifiManager.save(network, null);
                }
            }
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Test {@link WifiNetworkConnectionStatistics} does not crash.
     * TODO(b/150891569): deprecate it in Android S, this API is not used anywhere.
     */
    public void testWifiNetworkConnectionStatistics() {
        new WifiNetworkConnectionStatistics();
        WifiNetworkConnectionStatistics stats = new WifiNetworkConnectionStatistics(0, 0);
        new WifiNetworkConnectionStatistics(stats);
    }

    /**
     * Test that the wifi country code is either null, or a length-2 string.
     */
    public void testGetCountryCode() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }

        String wifiCountryCode = ShellIdentityUtils.invokeWithShellPermissions(
                mWifiManager::getCountryCode);

        if (wifiCountryCode == null) {
            return;
        }
        assertEquals(2, wifiCountryCode.length());

        // assert that the country code is all uppercase
        assertEquals(wifiCountryCode.toUpperCase(Locale.US), wifiCountryCode);

        String telephonyCountryCode = getContext().getSystemService(TelephonyManager.class)
                .getNetworkCountryIso();
        assertEquals(telephonyCountryCode, wifiCountryCode.toLowerCase(Locale.US));
    }

    /**
     * Test that {@link WifiManager#getCurrentNetwork()} returns a Network obeject consistent
     * with {@link ConnectivityManager#registerNetworkCallback} when connected to a Wifi network,
     * and returns null when not connected.
     */
    public void testGetCurrentNetwork() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }

        // wait for Wifi to be connected
        PollingCheck.check(
                "Wifi not connected - Please ensure there is a saved network in range of this "
                        + "device",
                20000,
                () -> mWifiManager.getConnectionInfo().getNetworkId() != -1);

        Network wifiCurrentNetwork = ShellIdentityUtils.invokeWithShellPermissions(
                mWifiManager::getCurrentNetwork);
        assertNotNull(wifiCurrentNetwork);

        TestNetworkCallback networkCallbackListener = new TestNetworkCallback(mLock);
        synchronized (mLock) {
            try {
                // File a request for wifi network.
                mConnectivityManager.registerNetworkCallback(
                        new NetworkRequest.Builder()
                                .addTransportType(TRANSPORT_WIFI)
                                .build(),
                        networkCallbackListener);
                // now wait for callback
                mLock.wait(DURATION);
            } catch (InterruptedException e) {
            }
        }
        assertTrue(networkCallbackListener.onAvailableCalled);
        Network connectivityCurrentNetwork = networkCallbackListener.network;
        assertEquals(connectivityCurrentNetwork, wifiCurrentNetwork);

        setWifiEnabled(false);
        PollingCheck.check(
                "Wifi not disconnected!",
                20000,
                () -> mWifiManager.getConnectionInfo().getNetworkId() == -1);

        assertNull(ShellIdentityUtils.invokeWithShellPermissions(mWifiManager::getCurrentNetwork));
    }

    /**
     * Tests {@link WifiManager#isWpa3SaeSupported()} does not crash.
     */
    public void testIsWpa3SaeSupported() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        mWifiManager.isWpa3SaeSupported();
    }

    /**
     * Tests {@link WifiManager#isWpa3SuiteBSupported()} does not crash.
     */
    public void testIsWpa3SuiteBSupported() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        mWifiManager.isWpa3SuiteBSupported();
    }

    /**
     * Tests {@link WifiManager#isEnhancedOpenSupported()} does not crash.
     */
    public void testIsEnhancedOpenSupported() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        mWifiManager.isEnhancedOpenSupported();
    }
}
