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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.wifi.WifiManager;
import android.net.wifi.aware.AttachCallback;
import android.net.wifi.aware.Characteristics;
import android.net.wifi.aware.IdentityChangedListener;
import android.net.wifi.aware.WifiAwareManager;
import android.net.wifi.aware.WifiAwareSession;
import android.test.AndroidTestCase;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Wi-Fi Aware CTS test suite: single device testing. Performs tests on a single
 * device to validate Wi-Fi Aware.
 */
public class SingleDeviceTest extends AndroidTestCase {
    private static final String TAG = "WifiAwareCtsTests";

    // wait for Wi-Fi Aware to become available
    static private final int WAIT_FOR_AWARE_CHANGE_SECS = 10;

    private final Object mLock = new Object();

    private WifiAwareManager mWifiAwareManager;
    private WifiManager mWifiManager;
    private WifiManager.WifiLock mWifiLock;

    // used to store any WifiAwareSession allocated during tests - will clean-up after tests
    private List<WifiAwareSession> mSessions = new ArrayList<>();

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

    private class AttachCallbackTest extends AttachCallback {
        static final int ATTACHED = 0;
        static final int ATTACH_FAILED = 1;
        static final int ERROR = 2; // no callback: timeout, interruption

        private CountDownLatch mBlocker = new CountDownLatch(1);
        private int mCallbackCalled = ERROR; // garbage init
        private WifiAwareSession mSession = null;

        @Override
        public void onAttached(WifiAwareSession session) {
            mCallbackCalled = ATTACHED;
            mSession = session;
            synchronized (mLock) {
                mSessions.add(session);
            }
            mBlocker.countDown();
        }

        @Override
        public void onAttachFailed() {
            mCallbackCalled = ATTACH_FAILED;
            mBlocker.countDown();
        }

        /**
         * Waits for any of the callbacks to be called - or an error (timeout, interruption).
         * Returns one of the ATTACHED, ATTACH_FAILED, or ERROR values.
         */
        int waitForAnyCallback() {
            try {
                boolean noTimeout = mBlocker.await(WAIT_FOR_AWARE_CHANGE_SECS, TimeUnit.SECONDS);
                if (noTimeout) {
                    return mCallbackCalled;
                } else {
                    return ERROR;
                }
            } catch (InterruptedException e) {
                return ERROR;
            }
        }

        /**
         * Access the session created by a callback. Only useful to be called after calling
         * waitForAnyCallback() and getting the ATTACHED code back.
         */
        WifiAwareSession getSession() {
            return mSession;
        }
    }

    private class IdentityChangedListenerTest extends IdentityChangedListener {
        private CountDownLatch mBlocker = new CountDownLatch(1);
        private byte[] mMac = null;

        @Override
        public void onIdentityChanged(byte[] mac) {
            mMac = mac;
            mBlocker.countDown();
        }

        /**
         * Waits for the listener callback to be called - or an error (timeout, interruption).
         * Returns true on callback called, false on error (timeout, interruption).
         */
        boolean waitForListener() {
            try {
                return mBlocker.await(WAIT_FOR_AWARE_CHANGE_SECS, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                return false;
            }
        }

        /**
         * Returns the MAC address of the discovery interface supplied to the triggered callback.
         */
        byte[] getMac() {
            return mMac;
        }
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        if (!TestUtils.shouldTestWifiAware(getContext())) {
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
        if (!TestUtils.shouldTestWifiAware(getContext())) {
            super.tearDown();
            return;
        }

        synchronized (mLock) {
            for (WifiAwareSession session : mSessions) {
                // no damage from destroying twice (i.e. ok if test cleaned up after itself already)
                session.destroy();
            }
            mSessions.clear();
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
        if (!TestUtils.shouldTestWifiAware(getContext())) {
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
        if (!TestUtils.shouldTestWifiAware(getContext())) {
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

    /**
     * Validate that can attach to Wi-Fi Aware.
     */
    public void testAttachNoIdentity() {
        if (!TestUtils.shouldTestWifiAware(getContext())) {
            return;
        }

        AttachCallbackTest attachCb = new AttachCallbackTest();
        mWifiAwareManager.attach(attachCb, null);
        int cbCalled = attachCb.waitForAnyCallback();
        assertEquals("Wi-Fi Aware attach", AttachCallbackTest.ATTACHED, cbCalled);

        WifiAwareSession session = attachCb.getSession();
        assertNotNull("Wi-Fi Aware session", session);

        session.destroy();
    }

    /**
     * Validate that can attach to Wi-Fi Aware and get identity information. Use the identity
     * information to validate that MAC address changes on every attach.
     *
     * Note: relies on no other entity using Wi-Fi Aware during the CTS test. Since if it is used
     * then the attach/destroy will not correspond to enable/disable and will not result in a new
     * MAC address being generated.
     */
    public void testAttachDiscoveryAddressChanges() {
        if (!TestUtils.shouldTestWifiAware(getContext())) {
            return;
        }

        final int numIterations = 10;
        Set<TestUtils.MacWrapper> macs = new HashSet<>();

        for (int i = 0; i < numIterations; ++i) {
            AttachCallbackTest attachCb = new AttachCallbackTest();
            IdentityChangedListenerTest identityL = new IdentityChangedListenerTest();
            mWifiAwareManager.attach(attachCb, identityL, null);
            assertEquals("Wi-Fi Aware attach: iteration " + i, AttachCallbackTest.ATTACHED,
                    attachCb.waitForAnyCallback());
            assertTrue("Wi-Fi Aware attach: iteration " + i, identityL.waitForListener());

            WifiAwareSession session = attachCb.getSession();
            assertNotNull("Wi-Fi Aware session: iteration " + i, session);

            byte[] mac = identityL.getMac();
            assertNotNull("Wi-Fi Aware discovery MAC: iteration " + i, mac);

            session.destroy();

            macs.add(new TestUtils.MacWrapper(mac));
        }

        assertEquals("", numIterations, macs.size());
    }
}
