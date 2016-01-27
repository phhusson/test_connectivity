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

import static android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_DISABLED;
import static android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED;
import static android.net.ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED;
import android.app.Activity;
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
