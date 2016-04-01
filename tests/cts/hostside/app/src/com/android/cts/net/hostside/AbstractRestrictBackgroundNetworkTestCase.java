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

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import android.app.ActivityManager;
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

    protected static final String TEST_PKG = "com.android.cts.net.hostside";
    protected static final String TEST_APP2_PKG = "com.android.cts.net.hostside.app2";

    private static final int SLEEP_TIME_SEC = 1;
    private static final boolean DEBUG = true;

    // Constants below must match values defined on app2's Common.java
    private static final String MANIFEST_RECEIVER = "ManifestReceiver";
    private static final String DYNAMIC_RECEIVER = "DynamicReceiver";
    private static final String ACTION_GET_COUNTERS =
            "com.android.cts.net.hostside.app2.action.GET_COUNTERS";
    private static final String ACTION_CHECK_NETWORK =
            "com.android.cts.net.hostside.app2.action.CHECK_NETWORK";
    private static final String ACTION_RECEIVER_READY =
            "com.android.cts.net.hostside.app2.action.RECEIVER_READY";
    private static final String EXTRA_ACTION = "com.android.cts.net.hostside.app2.extra.ACTION";
    private static final String EXTRA_RECEIVER_NAME =
            "com.android.cts.net.hostside.app2.extra.RECEIVER_NAME";
    private static final String RESULT_SEPARATOR = ";";
    private static final String STATUS_NETWORK_UNAVAILABLE_PREFIX = "NetworkUnavailable:";
    private static final String STATUS_NETWORK_AVAILABLE_PREFIX = "NetworkAvailable:";
    private static final int SECOND_IN_MS = 1000;
    private static final int NETWORK_TIMEOUT_MS = 15 * SECOND_IN_MS;
    private static final int PROCESS_STATE_FOREGROUND_SERVICE = 4;


    // Must be higher than NETWORK_TIMEOUT_MS
    private static final int ORDERED_BROADCAST_TIMEOUT_MS = NETWORK_TIMEOUT_MS * 4;

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
        mUid = getUid(TEST_APP2_PKG);
        final int myUid = getUid(mContext.getPackageName());

        Log.i(TAG, "Apps status on " + getName() + ":\n"
                + "\ttest app: uid=" + myUid + ", state=" + getProcessStateByUid(myUid) + "\n"
                + "\tapp2: uid=" + mUid + ", state=" + getProcessStateByUid(mUid));
   }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        if (mResetMeteredWifi) {
            setWifiMeteredStatus(false);
        }
    }

    protected int getUid(String packageName) throws Exception {
        return mContext.getPackageManager().getPackageUid(packageName, 0);
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
            Thread.sleep(SLEEP_TIME_SEC * SECOND_IN_MS);
        } while (attempts <= maxAttempts);
        assertEquals("Number of expected broadcasts for " + receiverName + " not reached after "
                + maxAttempts * SLEEP_TIME_SEC + " seconds", expectedCount, count);
    }

    protected String sendOrderedBroadcast(Intent intent) throws Exception {
        return sendOrderedBroadcast(intent, ORDERED_BROADCAST_TIMEOUT_MS);
    }

    protected String sendOrderedBroadcast(Intent intent, int timeoutMs) throws Exception {
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

        final String resultData = result.poll(timeoutMs, TimeUnit.MILLISECONDS);
        Log.d(TAG, "Ordered broadcast response: " + resultData);
        return resultData;
    }

    protected int getNumberBroadcastsReceived(String receiverName, String action) throws Exception {
        final Intent intent = new Intent(ACTION_GET_COUNTERS);
        intent.putExtra(EXTRA_ACTION, ACTION_RESTRICT_BACKGROUND_CHANGED);
        intent.putExtra(EXTRA_RECEIVER_NAME, receiverName);
        final String resultData = sendOrderedBroadcast(intent);
        assertNotNull("timeout waiting for ordered broadcast result", resultData);
        return Integer.valueOf(resultData);
    }

    protected void assertRestrictBackgroundStatus(int expectedApiStatus) throws Exception {
        assertBackgroundState(); // Sanity check.
        final Intent intent = new Intent(ACTION_CHECK_NETWORK);
        final String resultData = sendOrderedBroadcast(intent);
        final String[] resultItems = resultData.split(RESULT_SEPARATOR);
        final String actualApiStatus = toString(Integer.parseInt(resultItems[0]));
        // First asserts the API returns the proper value...
        assertEquals("wrong status", toString(expectedApiStatus), actualApiStatus);

        //...then the actual network status in the background thread.
        final String networkStatus = getNetworkStatus(resultItems);
        assertNetworkStatus(expectedApiStatus != RESTRICT_BACKGROUND_STATUS_ENABLED, networkStatus);
    }

    protected void assertBackgroundNetworkAccess(boolean expectAllowed) throws Exception {
        assertBackgroundState(); // Sanity check.
        final Intent intent = new Intent(ACTION_CHECK_NETWORK);
        final String resultData = sendOrderedBroadcast(intent);
        final String[] resultItems = resultData.split(RESULT_SEPARATOR);
        final String networkStatus = getNetworkStatus(resultItems);
        assertNetworkStatus(expectAllowed, networkStatus);
    }

    protected final void assertBackgroundState() throws Exception {
        final ProcessState state = getProcessStateByUid(mUid);
        Log.v(TAG, "assertBackgroundState(): status for app2 (" + mUid + "): " + state);
        final boolean isBackground = isBackground(state.state);
        assertTrue("App2 is not on background state: " + state, isBackground);
    }

    protected final void assertForegroundServiceState() throws Exception {
        final ProcessState state = getProcessStateByUid(mUid);
        Log.v(TAG, "assertForegroundServiceState(): status for app2 (" + mUid + "): " + state);
        assertEquals("App2 is not on foreground service state: " + state,
                PROCESS_STATE_FOREGROUND_SERVICE, state.state);
    }

    /**
     * Returns whether an app state should be considered "background" for restriction purposes.
     */
    protected boolean isBackground(int state) {
        return state >= PROCESS_STATE_FOREGROUND_SERVICE;
    }

    private String getNetworkStatus(String[] resultItems) {
        return resultItems.length < 2 ? null : resultItems[1];
    }

    private void assertNetworkStatus(boolean expectAvailable, String status) throws Exception {
        if (status == null) {
            Log.d(TAG, "timeout waiting for ordered broadcast");
            if (expectAvailable) {
                fail("did not get network status when access was allowed");
            }
            return;
        }
        final String expectedPrefix = expectAvailable ?
                STATUS_NETWORK_AVAILABLE_PREFIX : STATUS_NETWORK_UNAVAILABLE_PREFIX;
        assertTrue("Wrong network status (" + status + ") when expectedAvailable is "
                + expectAvailable, status.startsWith(expectedPrefix));
    }

    protected String executeShellCommand(String command) throws Exception {
        final String result = runShellCommand(mInstrumentation, command).trim();
        if (DEBUG) Log.d(TAG, "Command '" + command + "' returned '" + result + "'");
        return result;
    }

    /**
     * Runs a Shell command which is not expected to generate output.
     */
    protected void executeSilentShellCommand(String command) throws Exception {
        final String result = executeShellCommand(command);
        assertTrue("Command '" + command + "' failed: " + result, result.trim().isEmpty());
    }

    /**
     * Asserts the result of a command, wait and re-running it a couple times if necessary.
     */
    protected void assertDelayedShellCommand(String command, final String expectedResult)
            throws Exception {
        assertDelayedShellCommand(command, new ExpectResultChecker() {

            @Override
            public boolean isExpected(String result) {
                return expectedResult.equals(result);
            }

            @Override
            public String getExpected() {
                return expectedResult;
            }
        });
    }

    protected void assertDelayedShellCommand(String command, ExpectResultChecker checker)
            throws Exception {
        final int maxTries = 5;
        String result = "";
        for (int i = 1; i <= maxTries; i++) {
            result = executeShellCommand(command).trim();
            if (checker.isExpected(result)) return;
            Log.v(TAG, "Command '" + command + "' returned '" + result + " instead of '"
                    + checker.getExpected() + "' on attempt #" + i
                    + "; sleeping 1s before trying again");
            Thread.sleep(SECOND_IN_MS);
        }
        fail("Command '" + command + "' did not return '" + checker.getExpected() + "' after "
                + maxTries
                + " attempts. Last result: '" + result + "'");
    }

    protected void setMeteredNetwork() throws Exception {
        final NetworkInfo info = mCm.getActiveNetworkInfo();
        final boolean metered = mCm.isActiveNetworkMetered();
        if (metered) {
            Log.d(TAG, "Active network already metered: " + info);
            return;
        } else {
            Log.w(TAG, "Active network not metered: " + info);
        }
        final String netId = setWifiMeteredStatus(true);
        assertTrue("Could not set wifi '" + netId + "' as metered ("
                + mCm.getActiveNetworkInfo() +")", mCm.isActiveNetworkMetered());
        // Set flag so status is reverted on teardown.
        mResetMeteredWifi = true;
        // Sanity check.
        assertMeteredNetwork(netId, true);
    }

    private String setWifiMeteredStatus(boolean metered) throws Exception {
        // We could call setWifiEnabled() here, but it might take sometime to be in a consistent
        // state (for example, if one of the saved network is not properly authenticated), so it's
        // better to let the hostside test take care of that.
        assertTrue("wi-fi is disabled", mWfm.isWifiEnabled());
        // TODO: if it's not guaranteed the device has wi-fi, we need to change the tests
        // to make the actual verification of restrictions optional.
        final String ssid = mWfm.getConnectionInfo().getSSID();
        assertNotNull("null SSID", ssid);
        final String netId = ssid.trim().replaceAll("\"", ""); // remove quotes, if any.
        assertFalse("empty SSID", ssid.isEmpty());

        Log.i(TAG, "Setting wi-fi network " + netId + " metered status to " + metered);
        final String setCommand = "cmd netpolicy set metered-network " + netId + " " + metered;
        assertDelayedShellCommand(setCommand, "");

        return netId;
    }

    private void assertMeteredNetwork(String netId, boolean status) throws Exception {
        final String command = "cmd netpolicy list wifi-networks";
        final String expectedLine = netId + ";" + status;
        assertDelayedShellCommand(command, new ExpectResultChecker() {

            @Override
            public boolean isExpected(String result) {
                return result.contains(expectedLine);
            }

            @Override
            public String getExpected() {
                return "line containing " + expectedLine;
            }
        });
    }

    protected void setRestrictBackground(boolean enabled) throws Exception {
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
        assertRestrictBackground("restrict-background-whitelist", uid, expected);
    }

    protected void addRestrictBackgroundBlacklist(int uid) throws Exception {
        executeShellCommand("cmd netpolicy add restrict-background-blacklist " + uid);
        assertRestrictBackgroundBlacklist(uid, true);
    }

    protected void removeRestrictBackgroundBlacklist(int uid) throws Exception {
        executeShellCommand("cmd netpolicy remove restrict-background-blacklist " + uid);
        assertRestrictBackgroundBlacklist(uid, false);
    }

    protected void assertRestrictBackgroundBlacklist(int uid, boolean expected) throws Exception {
        assertRestrictBackground("restrict-background-blacklist", uid, expected);
    }

    private void assertRestrictBackground(String list, int uid, boolean expected) throws Exception {
        final int maxTries = 5;
        boolean actual = false;
        for (int i = 1; i <= maxTries; i++) {
            final String output =
                    executeShellCommand("cmd netpolicy list " + list);
            actual = output.contains(Integer.toString(uid));
            if (expected == actual) {
                return;
            }
            Log.v(TAG, list + " check for uid " + uid + " doesn't match yet (expected "
                    + expected + ", got " + actual + "); sleeping 1s before polling again");
            Thread.sleep(SECOND_IN_MS);
        }
        fail(list + " check for uid " + uid + " failed: expected " + expected + ", got " + actual);
    }

    protected void assertPowerSaveModeWhitelist(String packageName, boolean expected)
            throws Exception {
        // TODO: currently the power-save mode is behaving like idle, but once it changes, we'll
        // need to use netpolicy for whitelisting
        assertDelayedShellCommand("dumpsys deviceidle whitelist =" + packageName,
                Boolean.toString(expected));
    }

    protected void addPowerSaveModeWhitelist(String packageName) throws Exception {
        Log.i(TAG, "Adding package " + packageName + " to power-save-mode whitelist");
        // TODO: currently the power-save mode is behaving like idle, but once it changes, we'll
        // need to use netpolicy for whitelisting
        executeShellCommand("dumpsys deviceidle whitelist +" + packageName);
        assertPowerSaveModeWhitelist(packageName, true); // Sanity check
    }

    protected void removePowerSaveModeWhitelist(String packageName) throws Exception {
        Log.i(TAG, "Removing package " + packageName + " from power-save-mode whitelist");
        // TODO: currently the power-save mode is behaving like idle, but once it changes, we'll
        // need to use netpolicy for whitelisting
        executeShellCommand("dumpsys deviceidle whitelist -" + packageName);
        assertPowerSaveModeWhitelist(packageName, false); // Sanity check
    }

    protected void setPowerSaveMode(boolean enabled) throws Exception {
        Log.i(TAG, "Setting power mode to " + enabled);
        if (enabled) {
            executeSilentShellCommand("cmd battery unplug");
            executeSilentShellCommand("settings put global low_power 1");
        } else {
            executeSilentShellCommand("cmd battery reset");
        }
    }

    /**
     * Starts a service that will register a broadcast receiver to receive
     * {@code RESTRICT_BACKGROUND_CHANGE} intents.
     * <p>
     * The service must run in a separate app because otherwise it would be killed every time
     * {@link #runDeviceTests(String, String)} is executed.
     */
    protected void registerBroadcastReceiver() throws Exception {
        executeShellCommand("am startservice com.android.cts.net.hostside.app2/.MyService");
        // Wait until receiver is ready.
        final int maxTries = 5;
        for (int i = 1; i <= maxTries; i++) {
            final String message =
                    sendOrderedBroadcast(new Intent(ACTION_RECEIVER_READY), SECOND_IN_MS);
            Log.d(TAG, "app2 receiver acked: " + message);
            if (message != null) {
                return;
            }
            Log.v(TAG, "app2 receiver is not ready yet; sleeping 1s before polling again");
            Thread.sleep(SECOND_IN_MS);
        }
        fail("app2 receiver is not ready");
    }

    protected void startForegroundService() throws Exception {
        executeShellCommand(
                "am startservice com.android.cts.net.hostside.app2/.MyForegroundService");
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

    private ProcessState getProcessStateByUid(int uid) throws Exception {
        return new ProcessState(executeShellCommand("cmd activity get-uid-state " + uid));
    }

    private static class ProcessState {
        private final String fullState;
        final int state;

        ProcessState(String fullState) {
            this.fullState = fullState;
            try {
                this.state = Integer.parseInt(fullState.split(" ")[0]);
            } catch (Exception e) {
                throw new IllegalArgumentException("Could not parse " + fullState);
            }
        }

        @Override
        public String toString() {
            return fullState;
        }
    }

    protected static interface ExpectResultChecker {
        boolean isExpected(String result);
        String getExpected();
    }
}
