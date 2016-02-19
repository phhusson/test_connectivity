/*
 * Copyright (C) 2016 The Android Open Source Project
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

package com.android.cts.net.hostside;

import static android.cts.util.SystemUtil.runShellCommand;
import static android.net.ConnectivityManager.ACTION_RESTRICT_BACKGROUND_CHANGED;
import static android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_DISABLED;
import static android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED;
import static android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED;

import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import android.app.Instrumentation;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.test.InstrumentationTestCase;
import android.util.Log;

/**
 * Superclass for tests related to background network restrictions.
 */
abstract class AbstractRestrictBackgroundNetworkTestCase extends InstrumentationTestCase {
    protected static final String TAG = "RestrictBackgroundNetworkTests";

    private static final String TEST_APP2_PKG = "com.android.cts.net.hostside.app2";

    private static final int SLEEP_TIME_SEC = 1;
    private static final boolean DEBUG = true;

    // Constants below must match values defined on app2's Common.java
    private static final String MANIFEST_RECEIVER = "ManifestReceiver";
    private static final String DYNAMIC_RECEIVER = "DynamicReceiver";
    private static final String ACTION_GET_COUNTERS =
            "com.android.cts.net.hostside.app2.action.GET_COUNTERS";
    private static final String ACTION_CHECK_NETWORK =
            "com.android.cts.net.hostside.app2.action.CHECK_NETWORK";
    private static final String EXTRA_ACTION = "com.android.cts.net.hostside.app2.extra.ACTION";
    private static final String EXTRA_RECEIVER_NAME =
            "com.android.cts.net.hostside.app2.extra.RECEIVER_NAME";
    private static final String RESULT_SEPARATOR = ";";
    private static final String STATUS_NETWORK_UNAVAILABLE_PREFIX = "NetworkUnavailable:";
    private static final String STATUS_NETWORK_AVAILABLE_PREFIX = "NetworkAvailable:";

    protected Context mContext;
    protected Instrumentation mInstrumentation;
    protected ConnectivityManager mCm;
    protected WifiManager mWfm;
    protected int mUid;
    private boolean mResetMeteredWifi = false;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        mInstrumentation = getInstrumentation();
        mContext = mInstrumentation.getContext();
        mCm = (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        mWfm = (WifiManager) mContext.getSystemService(Context.WIFI_SERVICE);
        mUid = mContext.getPackageManager().getPackageInfo(TEST_APP2_PKG, 0).applicationInfo.uid;
        final int myUid = mContext.getPackageManager()
                .getPackageInfo(mContext.getPackageName(), 0).applicationInfo.uid;

        Log.d(TAG, "UIDS: test app=" + myUid + ", app2=" + mUid);

        setMeteredNetwork();
   }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        if (mResetMeteredWifi) {
            setWifiMeteredStatus(false);
        }
    }

    protected void assertRestrictBackgroundChangedReceived(int expectedCount) throws Exception {
        assertRestrictBackgroundChangedReceived(DYNAMIC_RECEIVER, expectedCount);
        assertRestrictBackgroundChangedReceived(MANIFEST_RECEIVER, 0);
    }

    protected void assertRestrictBackgroundChangedReceived(String receiverName, int expectedCount)
            throws Exception {
        int attempts = 0;
        int count = 0;
        final int maxAttempts = 5;
        do {
            attempts++;
            count = getNumberBroadcastsReceived(receiverName, ACTION_RESTRICT_BACKGROUND_CHANGED);
            if (count == expectedCount) {
                break;
            }
            Log.d(TAG, "Expecting count " + expectedCount + " but actual is " + count + " after "
                    + attempts + " attempts; sleeping "
                    + SLEEP_TIME_SEC + " seconds before trying again");
            Thread.sleep(SLEEP_TIME_SEC * 1000);
        } while (attempts <= maxAttempts);
        assertEquals("Number of expected broadcasts for " + receiverName + " not reached after "
                + maxAttempts * SLEEP_TIME_SEC + " seconds", expectedCount, count);
    }

    protected String sendOrderedBroadcast(Intent intent) throws Exception {
        final LinkedBlockingQueue<String> result = new LinkedBlockingQueue<>(1);
        Log.d(TAG, "Sending ordered broadcast: " + intent);
        mContext.sendOrderedBroadcast(intent, null, new BroadcastReceiver() {

            @Override
            public void onReceive(Context context, Intent intent) {
                final String resultData = getResultData();
                if (resultData == null) {
                    Log.e(TAG, "Received null data from ordered intent");
                    return;
                }
                result.offer(resultData);
            }
        }, null, 0, null, null);

        final String resultData = result.poll(60, TimeUnit.SECONDS);
        assertNotNull("timeout waiting for ordered broadcast result", resultData);
        Log.d(TAG, "Ordered broadcast response: " + resultData);
        return resultData;
    }

    protected int getNumberBroadcastsReceived(String receiverName, String action) throws Exception {
        final Intent intent = new Intent(ACTION_GET_COUNTERS);
        intent.putExtra(EXTRA_ACTION, ACTION_RESTRICT_BACKGROUND_CHANGED);
        intent.putExtra(EXTRA_RECEIVER_NAME, receiverName);
        final String resultData = sendOrderedBroadcast(intent);
        return Integer.valueOf(resultData);
    }

    protected void assertRestrictBackgroundStatus(int expectedApiStatus) throws Exception {
        final Intent intent = new Intent(ACTION_CHECK_NETWORK);
        final String resultData = sendOrderedBroadcast(intent);
        final String[] resultItems = resultData.split(RESULT_SEPARATOR);
        final String actualApiStatus = toString(Integer.parseInt(resultItems[0]));
        final String actualNetworkStatus = resultItems[1];

        // First asserts the API returns the proper value...
        assertEquals("wrong status", toString(expectedApiStatus), actualApiStatus);

        //...then the actual network status in the background thread.
        final String expectedPrefix = expectedApiStatus == RESTRICT_BACKGROUND_STATUS_ENABLED ?
                        STATUS_NETWORK_UNAVAILABLE_PREFIX : STATUS_NETWORK_AVAILABLE_PREFIX;
        assertTrue("Wrong network status for API status " + actualApiStatus + ": "
                + actualNetworkStatus, actualNetworkStatus.startsWith(expectedPrefix));
    }

    protected String executeShellCommand(String command) throws IOException {
        final String result = runShellCommand(mInstrumentation, command).trim();
        if (DEBUG) Log.d(TAG, "Command '" + command + "' returned '" + result + "'");
        return result;
    }

    protected void setMeteredNetwork() throws IOException {
        final NetworkInfo info = mCm.getActiveNetworkInfo();
        final boolean metered = mCm.isActiveNetworkMetered();
        if (metered) {
            Log.d(TAG, "Active network already metered: " + info);
            return;
        }
        final String netId = setWifiMeteredStatus(true);
        assertTrue("Could not set wifi '" + netId + "' as metered ("
                + mCm.getActiveNetworkInfo() +")", mCm.isActiveNetworkMetered());
        // Set flag so status is reverted on teardown.
        mResetMeteredWifi = true;
    }

    protected String setWifiMeteredStatus(boolean metered) throws IOException {
        mWfm.setWifiEnabled(true);
        // TODO: if it's not guaranteed the device has wi-fi, we need to change the tests
        // to make the actual verification of restrictions optional.
        final String ssid = mWfm.getConnectionInfo().getSSID();
        assertNotNull("null SSID", ssid);
        final String netId = ssid.trim().replaceAll("\"", ""); // remove quotes, if any.
        assertFalse("empty SSID", ssid.isEmpty());

        Log.i(TAG, "Setting wi-fi network " + netId + " metered status to " + metered);
        final String setCommand = "cmd netpolicy set metered-network " + netId + " " + metered;
        final String result = executeShellCommand(setCommand);
        assertTrue("Command '" + setCommand + "' failed: " + result, result.isEmpty());

        // Sanity check.
        final String newStatus = executeShellCommand("cmd netpolicy get metered-network " + netId);
        assertEquals("Metered status of wi-fi network " + netId + " not set properly",
                newStatus.trim(), Boolean.toString(metered));
        return netId;
    }

    protected void setRestrictBackground(boolean enabled) throws IOException {
        executeShellCommand("cmd netpolicy set restrict-background " + enabled);
        final String output = executeShellCommand("cmd netpolicy get restrict-background ");
        final String expectedSuffix = enabled ? "enabled" : "disabled";
        // TODO: use MoreAsserts?
        assertTrue("output '" + output + "' should end with '" + expectedSuffix + "'",
                output.endsWith(expectedSuffix));
      }

    protected void addRestrictBackgroundWhitelist(int uid) throws Exception {
        executeShellCommand("cmd netpolicy add restrict-background-whitelist " + uid);
        assertRestrictBackgroundWhitelist(uid, true);
    }

    protected void removeRestrictBackgroundWhitelist(int uid) throws Exception {
        executeShellCommand("cmd netpolicy remove restrict-background-whitelist " + uid);
        assertRestrictBackgroundWhitelist(uid, false);
    }

    protected void assertRestrictBackgroundWhitelist(int uid, boolean expected) throws Exception {
        final int maxTries = 5;
        boolean actual = false;
        for (int i = 1; i <= maxTries; i++) {
            final String output =
                    executeShellCommand("cmd netpolicy list restrict-background-whitelist ");
            actual = output.contains(Integer.toString(uid));
            if (expected == actual) {
                return;
            }
            Log.v(TAG, "whitelist check for uid " + uid + " doesn't match yet (expected "
                    + expected + ", got " + actual + "); sleeping 1s before polling again");
            Thread.sleep(1000);
        }
        fail("whitelist check for uid " + uid + " failed: expected " + expected + ", got " + actual);
    }

    /**
     * Starts a service that will register a broadcast receiver to receive
     * {@code RESTRICT_BACKGROUND_CHANGE} intents.
     * <p>
     * The service must run in a separate app because otherwise it would be killed every time
     * {@link #runDeviceTests(String, String)} is executed.
     */
    protected void registerApp2BroadcastReceiver() throws IOException {
        executeShellCommand("am startservice com.android.cts.net.hostside.app2/.MyService");
    }

    private String toString(int status) {
        switch (status) {
            case RESTRICT_BACKGROUND_STATUS_DISABLED:
                return "DISABLED";
            case RESTRICT_BACKGROUND_STATUS_WHITELISTED:
                return "WHITELISTED";
            case RESTRICT_BACKGROUND_STATUS_ENABLED:
                return "ENABLED";
            default:
                return "UNKNOWN_STATUS_" + status;
        }
    }
}
