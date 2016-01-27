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

import static android.net.ConnectivityManager.ACTION_RESTRICT_BACKGROUND_CHANGED;
import static android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_DISABLED;
import static android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED;
import static android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.test.InstrumentationTestCase;
import android.util.Log;

/**
 * Tests for the {@link ConnectivityManager} API.
 *
 * <p>These tests rely on a host-side test to use {@code adb shell cmd netpolicy} to put the device
 * in the proper state. In fact, they're more like "assertions" than tests per se - the real test
 * logic is done on {@code HostsideNetworkTests}.
 */
public class ConnectivityManagerTest extends InstrumentationTestCase {
    private static final String TAG = "ConnectivityManagerTest";

    static final String MANIFEST_RECEIVER = "ManifestReceiver";
    static final String DYNAMIC_RECEIVER = "DynamicReceiver";

    private ConnectivityManager mCM;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        mCM = (ConnectivityManager) getInstrumentation().getContext().getSystemService(
                Activity.CONNECTIVITY_SERVICE);
   }

    public void testGetRestrictBackgroundStatus_disabled() {
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_DISABLED);
    }

    public void testGetRestrictBackgroundStatus_whitelisted() {
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_WHITELISTED);
    }

    public void testGetRestrictBackgroundStatus_enabled() {
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);
    }

    public void testRestrictBackgroundChangedReceivedOnce() throws Exception {
        assertRestrictBackgroundChangedReceived(DYNAMIC_RECEIVER, 1);
        assertRestrictBackgroundChangedReceived(MANIFEST_RECEIVER, 0);
    }

    public void testRestrictBackgroundChangedReceivedTwice() throws Exception {
        assertRestrictBackgroundChangedReceived(DYNAMIC_RECEIVER, 2);
        assertRestrictBackgroundChangedReceived(MANIFEST_RECEIVER, 0);
    }

    private void assertRestrictBackgroundChangedReceived(String receiverName, int expectedCount)
            throws Exception {
        int attempts = 0;
        int count = 0;
        final int maxAttempts = 5;
        final int sleepTime = 10;
        do {
            attempts++;
            count = getNumberBroadcastsReceived(getInstrumentation().getContext(), receiverName,
                    ACTION_RESTRICT_BACKGROUND_CHANGED);
            if (count == expectedCount) {
                break;
            }
            Log.d(TAG, "Count is " + count + " after " + attempts + " attempts; sleeping "
                    + sleepTime + " seconds before trying again");
            Thread.sleep(sleepTime * 1000);
        } while (attempts <= maxAttempts);
        assertEquals("Number of expected broadcasts for " + receiverName + " not reached after "
                + maxAttempts * sleepTime + " seconds", expectedCount, count);
    }

    static int getNumberBroadcastsReceived(Context context, String receiverName, String action)
            throws Exception {
        final Context sharedContext = context.createPackageContext(
                "com.android.cts.net.hostside.app2", Context.CONTEXT_IGNORE_SECURITY);
        final SharedPreferences prefs = sharedContext.getSharedPreferences(receiverName,
                Context.MODE_PRIVATE);
        return prefs.getInt(action, 0);
    }

    private void assertRestrictBackgroundStatus(int expectedStatus) {
        final String expected = toString(expectedStatus);
        Log.d(TAG, getName() + " (expecting " + expected + ")");
        final int actualStatus = mCM.getRestrictBackgroundStatus();
        assertEquals("wrong status", expected, toString(actualStatus));
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
