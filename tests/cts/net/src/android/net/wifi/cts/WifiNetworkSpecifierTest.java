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

package android.net.wifi.cts;

import static android.net.NetworkCapabilitiesProto.TRANSPORT_WIFI;

import static com.google.common.truth.Truth.assertThat;

import android.app.UiAutomation;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiManager.NetworkRequestMatchCallback;
import android.net.wifi.WifiNetworkSpecifier;
import android.platform.test.annotations.AppModeFull;
import android.support.test.uiautomator.UiDevice;
import android.test.AndroidTestCase;

import androidx.test.platform.app.InstrumentationRegistry;

import com.android.compatibility.common.util.PollingCheck;
import com.android.compatibility.common.util.ShellIdentityUtils;
import com.android.compatibility.common.util.SystemUtil;

import java.util.List;
import java.util.concurrent.Executors;

/**
 * Tests the entire connection flow using {@link WifiNetworkSpecifier} embedded in a
 * {@link NetworkRequest} & passed into {@link ConnectivityManager#requestNetwork(NetworkRequest,
 * ConnectivityManager.NetworkCallback)}.
 *
 * Assumes that all the saved networks is either open/WPA1/WPA2/WPA3 authenticated network.
 */
@AppModeFull(reason = "Cannot get WifiManager in instant app mode")
public class WifiNetworkSpecifierTest extends AndroidTestCase {
    private static final String TAG = "WifiNetworkSpecifierTest";

    private WifiManager mWifiManager;
    private ConnectivityManager mConnectivityManager;
    private UiDevice mUiDevice;
    private final Object mLock = new Object();
    private final Object mUiLock = new Object();
    private WifiConfiguration mTestNetwork;
    private boolean mWasVerboseLoggingEnabled;

    private static final int DURATION = 10_000;
    private static final int DURATION_UI_INTERACTION = 15_000;
    private static final int DURATION_NETWORK_CONNECTION = 30_000;
    private static final int DURATION_SCREEN_TOGGLE = 2000;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        mWifiManager = (WifiManager) getContext().getSystemService(Context.WIFI_SERVICE);
        mConnectivityManager = getContext().getSystemService(ConnectivityManager.class);
        assertNotNull(mWifiManager);

        // turn on verbose logging for tests
        mWasVerboseLoggingEnabled = ShellIdentityUtils.invokeWithShellPermissions(
                () -> mWifiManager.isVerboseLoggingEnabled());
        ShellIdentityUtils.invokeWithShellPermissions(
                () -> mWifiManager.setVerboseLoggingEnabled(true));

        if (!mWifiManager.isWifiEnabled()) setWifiEnabled(true);
        mUiDevice = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation());
        turnScreenOn();
        PollingCheck.check("Wifi not enabled", DURATION, () -> mWifiManager.isWifiEnabled());

        List<WifiConfiguration> savedNetworks = ShellIdentityUtils.invokeWithShellPermissions(
                () -> mWifiManager.getPrivilegedConfiguredNetworks());
        assertFalse("Need at least one saved network", savedNetworks.isEmpty());
        // Pick any one of the saved networks on the device (assumes that it is in range)
        mTestNetwork = savedNetworks.get(0);
    }

    @Override
    protected void tearDown() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            super.tearDown();
            return;
        }
        if (!mWifiManager.isWifiEnabled()) setWifiEnabled(true);
        turnScreenOff();
        ShellIdentityUtils.invokeWithShellPermissions(
                () -> mWifiManager.setVerboseLoggingEnabled(mWasVerboseLoggingEnabled));
        super.tearDown();
    }

    private void setWifiEnabled(boolean enable) throws Exception {
        // now trigger the change using shell commands.
        SystemUtil.runShellCommand("svc wifi " + (enable ? "enable" : "disable"));
    }

    private void turnScreenOn() throws Exception {
        mUiDevice.executeShellCommand("input keyevent KEYCODE_WAKEUP");
        mUiDevice.executeShellCommand("wm dismiss-keyguard");
        // Since the screen on/off intent is ordered, they will not be sent right now.
        Thread.sleep(DURATION_SCREEN_TOGGLE);
    }

    private void turnScreenOff() throws Exception {
        mUiDevice.executeShellCommand("input keyevent KEYCODE_SLEEP");
        // Since the screen on/off intent is ordered, they will not be sent right now.
        Thread.sleep(DURATION_SCREEN_TOGGLE);
    }

    private static class TestNetworkCallback extends ConnectivityManager.NetworkCallback {
        private final Object mLock;
        public boolean onAvailableCalled = false;
        public NetworkCapabilities networkCapabilities;

        TestNetworkCallback(Object lock) {
            mLock = lock;
        }

        @Override
        public void onAvailable(Network network, NetworkCapabilities networkCapabilities,
                LinkProperties linkProperties, boolean blocked) {
            synchronized (mLock) {
                onAvailableCalled = true;
                this.networkCapabilities = networkCapabilities;
                mLock.notify();
            }
        }
    }

    private static class TestNetworkRequestMatchCallback implements NetworkRequestMatchCallback {
        private final Object mLock;

        public boolean onRegistrationCalled = false;
        public boolean onAbortCalled = false;
        public boolean onMatchCalled = false;
        public boolean onConnectSuccessCalled = false;
        public boolean onConnectFailureCalled = false;
        public WifiManager.NetworkRequestUserSelectionCallback userSelectionCallback = null;
        public List<ScanResult> matchedScanResults = null;

        TestNetworkRequestMatchCallback(Object lock) {
            mLock = lock;
        }

        @Override
        public void onUserSelectionCallbackRegistration(
                WifiManager.NetworkRequestUserSelectionCallback userSelectionCallback) {
            synchronized (mLock) {
                onRegistrationCalled = true;
                this.userSelectionCallback = userSelectionCallback;
                mLock.notify();
            }
        }

        @Override
        public void onAbort() {
            synchronized (mLock) {
                onAbortCalled = true;
                mLock.notify();
            }
        }

        @Override
        public void onMatch(List<ScanResult> scanResults) {
            synchronized (mLock) {
                // This can be invoked multiple times. So, ignore after the first one to avoid
                // disturbing the rest of the test sequence.
                if (onMatchCalled) return;
                onMatchCalled = true;
                matchedScanResults = scanResults;
                mLock.notify();
            }
        }

        @Override
        public void onUserSelectionConnectSuccess(WifiConfiguration config) {
            synchronized (mLock) {
                onConnectSuccessCalled = true;
                mLock.notify();
            }
        }

        @Override
        public void onUserSelectionConnectFailure(WifiConfiguration config) {
            synchronized (mLock) {
                onConnectFailureCalled = true;
                mLock.notify();
            }
        }
    }

    private WifiNetworkSpecifier createSpecifierWithSpecificSsidFromSavedNetwork() {
        WifiNetworkSpecifier.Builder specifierBuilder = new WifiNetworkSpecifier.Builder()
                .setSsid(WifiInfo.sanitizeSsid(mTestNetwork.SSID));
        if (mTestNetwork.preSharedKey != null) {
            if (mTestNetwork.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.WPA_PSK)) {
                specifierBuilder.setWpa2Passphrase(mTestNetwork.preSharedKey);
            } else if (mTestNetwork.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.SAE)) {
                specifierBuilder.setWpa3Passphrase(mTestNetwork.preSharedKey);
            } else {
                fail("Unsupported security type found in saved networks");
            }
        } else if (!mTestNetwork.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.NONE)) {
            fail("Unsupported security type found in saved networks");
        }
        return specifierBuilder.build();
    }

    private void handleUiInteractions() {
        UiAutomation uiAutomation = InstrumentationRegistry.getInstrumentation().getUiAutomation();
        TestNetworkRequestMatchCallback networkRequestMatchCallback =
                new TestNetworkRequestMatchCallback(mUiLock);
        try {
            uiAutomation.adoptShellPermissionIdentity();

            // 1. Wait for registration callback.
            synchronized (mUiLock) {
                try {
                    mWifiManager.registerNetworkRequestMatchCallback(
                            Executors.newSingleThreadExecutor(), networkRequestMatchCallback);
                    // now wait for the registration callback first.
                    mUiLock.wait(DURATION_UI_INTERACTION);
                } catch (InterruptedException e) {
                }
            }
            assertTrue(networkRequestMatchCallback.onRegistrationCalled);
            assertNotNull(networkRequestMatchCallback.userSelectionCallback);

            // 2. Wait for matching scan results
            synchronized (mUiLock) {
                try {
                    // now wait for the registration callback first.
                    mUiLock.wait(DURATION_UI_INTERACTION);
                } catch (InterruptedException e) {
                }
            }
            assertTrue(networkRequestMatchCallback.onMatchCalled);
            assertNotNull(networkRequestMatchCallback.matchedScanResults);
            assertThat(networkRequestMatchCallback.matchedScanResults.size()).isAtLeast(1);

            // 3. Trigger connection to one of the matched networks (should be 1 in all cases).
            networkRequestMatchCallback.userSelectionCallback.select(mTestNetwork);

            // 4. Wait for connection success.
            synchronized (mUiLock) {
                try {
                    // now wait for the registration callback first.
                    mUiLock.wait(DURATION_UI_INTERACTION);
                } catch (InterruptedException e) {
                }
            }
            assertTrue(networkRequestMatchCallback.onConnectSuccessCalled);
        } finally {
            mWifiManager.unregisterNetworkRequestMatchCallback(networkRequestMatchCallback);
            uiAutomation.dropShellPermissionIdentity();
        }
    }

    /**
     * Tests the entire connection flow using a specific SSID in the specifier.
     */
    public void testConnectWithSpecificSsid() {
        WifiNetworkSpecifier specifier = createSpecifierWithSpecificSsidFromSavedNetwork();

        // Fork a thread to handle the UI interactions.
        Thread uiThread = new Thread(() -> handleUiInteractions());

        // File the network request & wait for the callback.
        TestNetworkCallback networkCallbackListener = new TestNetworkCallback(mLock);
        synchronized (mLock) {
            try {
                // File a request for wifi network.
                mConnectivityManager.requestNetwork(
                        new NetworkRequest.Builder()
                                .addTransportType(TRANSPORT_WIFI)
                                .setNetworkSpecifier(specifier)
                                .build(),
                        networkCallbackListener);
                // Start the UI interactions.
                uiThread.run();
                // now wait for callback
                mLock.wait(DURATION_NETWORK_CONNECTION);
            } catch (InterruptedException e) {
            }
        }
        assertTrue(networkCallbackListener.onAvailableCalled);

        try {
            // Ensure that the UI interaction thread has completed.
            uiThread.join(DURATION_UI_INTERACTION);
        } catch (InterruptedException e) {
            fail("UI interaction interrupted");
        }

        // Release the request after the test.
        mConnectivityManager.unregisterNetworkCallback(networkCallbackListener);
    }
}
