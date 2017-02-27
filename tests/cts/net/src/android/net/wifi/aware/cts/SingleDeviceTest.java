/*
 * Copyright (C) 2017 The Android Open Source Project
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

package android.net.wifi.aware.cts;

import static android.net.wifi.aware.cts.TestUtils.shouldTestWifiAware;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.WifiManager;
import android.net.wifi.aware.Characteristics;
import android.net.wifi.aware.WifiAwareManager;
import android.test.AndroidTestCase;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Wi-Fi Aware CTS test suite: single device testing. Performs tests on a single
 * device to validate Wi-Fi Aware.
 */
public class SingleDeviceTest extends AndroidTestCase {
    static private final String TAG = "WifiAwareCtsTests";

    // wait for Wi-Fi Aware to become available
    static private final int WAIT_FOR_AWARE_CHANGE_SECS = 10;

    private WifiAwareManager mWifiAwareManager;
    private WifiManager mWifiManager;
    private WifiManager.WifiLock mWifiLock;

    private class WifiAwareBroadcastReceiver extends BroadcastReceiver {
        private CountDownLatch mBlocker = new CountDownLatch(1);

        @Override
        public void onReceive(Context context, Intent intent) {
            if (WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED.equals(intent.getAction())) {
                mBlocker.countDown();
            }
        }

        boolean waitForStateChange() throws InterruptedException {
            return mBlocker.await(WAIT_FOR_AWARE_CHANGE_SECS, TimeUnit.SECONDS);
        }
    };

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        if (!shouldTestWifiAware(getContext())) {
            return;
        }

        mWifiAwareManager = (WifiAwareManager) getContext().getSystemService(
                Context.WIFI_AWARE_SERVICE);
        assertNotNull("Wi-Fi Aware Manager", mWifiAwareManager);

        mWifiManager = (WifiManager) getContext().getSystemService(Context.WIFI_SERVICE);
        assertNotNull("Wi-Fi Manager", mWifiManager);
        mWifiLock = mWifiManager.createWifiLock(TAG);
        mWifiLock.acquire();
        if (!mWifiManager.isWifiEnabled()) {
            mWifiManager.setWifiEnabled(true);
        }

        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED);
        WifiAwareBroadcastReceiver receiver = new WifiAwareBroadcastReceiver();
        mContext.registerReceiver(receiver, intentFilter);
        if (!mWifiAwareManager.isAvailable()) {
            assertTrue("Timeout waiting for Wi-Fi Aware to change status",
                    receiver.waitForStateChange());
            assertTrue("Wi-Fi Aware is not available (should be)", mWifiAwareManager.isAvailable());
        }
    }

    @Override
    protected void tearDown() throws Exception {
        if (!shouldTestWifiAware(getContext())) {
            super.tearDown();
            return;
        }

        super.tearDown();
    }

    /**
     * Validate:
     * - Characteristics are available
     * - Characteristics values are legitimate. Not in the CDD. However, the tested values are
     *   based on the Wi-Fi Aware protocol.
     */
    public void testCharacteristics() {
        if (!shouldTestWifiAware(getContext())) {
            return;
        }

        Characteristics characteristics = mWifiAwareManager.getCharacteristics();
        assertNotNull("Wi-Fi Aware characteristics are null", characteristics);
        assertEquals("Service Name Length", characteristics.getMaxServiceNameLength(), 255);
        assertEquals("Service Specific Information Length",
                characteristics.getMaxServiceSpecificInfoLength(), 255);
        assertEquals("Match Filter Length", characteristics.getMaxMatchFilterLength(), 255);
    }

    /**
     * Validate that on Wi-Fi Aware availability change we get a broadcast + the API returns
     * correct status.
     */
    public void testAvailabilityStatusChange() throws Exception {
        if (!shouldTestWifiAware(getContext())) {
            return;
        }

        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(WifiAwareManager.ACTION_WIFI_AWARE_STATE_CHANGED);

        // 1. Disable Wi-Fi
        WifiAwareBroadcastReceiver receiver1 = new WifiAwareBroadcastReceiver();
        mContext.registerReceiver(receiver1, intentFilter);
        mWifiManager.setWifiEnabled(false);

        assertTrue("Timeout waiting for Wi-Fi Aware to change status",
                receiver1.waitForStateChange());
        assertFalse("Wi-Fi Aware is available (should not be)", mWifiAwareManager.isAvailable());

        // 2. Enable Wi-Fi
        WifiAwareBroadcastReceiver receiver2 = new WifiAwareBroadcastReceiver();
        mContext.registerReceiver(receiver2, intentFilter);
        mWifiManager.setWifiEnabled(true);

        assertTrue("Timeout waiting for Wi-Fi Aware to change status",
                receiver2.waitForStateChange());
        assertTrue("Wi-Fi Aware is not available (should be)", mWifiAwareManager.isAvailable());
    }
}
