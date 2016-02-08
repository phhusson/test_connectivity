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

package com.android.cts.net;

import com.android.ddmlib.Log;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.device.WifiHelper;

public class HostsideRestrictBackgroundNetworkTests extends HostsideNetworkTestCase {
    private static final String TEST_APP2_PKG = "com.android.cts.net.hostside.app2";
    private static final String TEST_APP2_APK = "CtsHostsideNetworkTestsApp2.apk";

    private int mUid;
    private WifiHelper mWifiHelper;

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        mUid = getUid(TEST_PKG);
        mWifiHelper = new WifiHelper(getDevice());

        setWifiMeteredStatus(true);
        setRestrictBackground(false);

        uninstallPackage(TEST_APP2_PKG, false);
        installPackage(TEST_APP2_APK);

        startBroadcastReceiverService();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        uninstallPackage(TEST_APP2_PKG, true);
        setRestrictBackground(false);
        setWifiMeteredStatus(false);
    }

    public void testGetRestrictBackgroundStatus_disabled() throws Exception {
        removeRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundStatusDisabled();
        assertRestrictBackgroundChangedReceivedOnce();

        // Sanity check: make sure status is always disabled, never whitelisted
        addRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundStatusDisabled();
        assertRestrictBackgroundChangedReceivedTwice();
    }

    public void testGetRestrictBackgroundStatus_whitelisted() throws Exception {
        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceivedOnce();

        addRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundStatusWhitelisted();
        assertRestrictBackgroundChangedReceivedTwice();
    }

    public void testGetRestrictBackgroundStatus_enabled() throws Exception {
        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceivedOnce();

        removeRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundStatusEnabled();
        assertRestrictBackgroundChangedReceivedTwice();
    }

    public void testGetRestrictBackgroundStatus_uninstall() throws Exception {
        addRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundWhitelist(mUid, true);

        uninstallPackage(TEST_PKG, true);
        assertPackageUninstalled(TEST_PKG);
        assertRestrictBackgroundWhitelist(mUid, false);

        installPackage(TEST_APK);
        final int newUid = getUid(TEST_PKG);
        assertRestrictBackgroundWhitelist(mUid, false);
        assertRestrictBackgroundWhitelist(newUid, false);
    }

    /**
     * Starts a service that will register a broadcast receiver to receive
     * {@code RESTRICT_BACKGROUND_CHANGE} intents.
     * <p>
     * The service must run in a separate app because otherwise it would be killed every time
     * {@link #runDeviceTests(String, String)} is executed.
     */
    private void startBroadcastReceiverService() throws DeviceNotAvailableException {
        runCommand("am startservice " + TEST_APP2_PKG + "/.MyService");
    }

    private void assertRestrictBackgroundStatusDisabled() throws DeviceNotAvailableException {
        runDeviceTests(TEST_PKG, TEST_PKG + ".ConnectivityManagerTest",
                "testGetRestrictBackgroundStatus_disabled");
    }

    private void assertRestrictBackgroundStatusWhitelisted() throws DeviceNotAvailableException {
        runDeviceTests(TEST_PKG, TEST_PKG + ".ConnectivityManagerTest",
                "testGetRestrictBackgroundStatus_whitelisted");
    }

    private void assertRestrictBackgroundStatusEnabled() throws DeviceNotAvailableException {
        runDeviceTests(TEST_PKG, TEST_PKG + ".ConnectivityManagerTest",
                "testGetRestrictBackgroundStatus_enabled");
    }

    private void assertRestrictBackgroundChangedReceivedOnce() throws DeviceNotAvailableException {
        runDeviceTests(TEST_PKG, TEST_PKG + ".ConnectivityManagerTest",
                "testRestrictBackgroundChangedReceivedOnce");
    }

    private void assertRestrictBackgroundChangedReceivedTwice() throws DeviceNotAvailableException {
        runDeviceTests(TEST_PKG, TEST_PKG + ".ConnectivityManagerTest",
                "testRestrictBackgroundChangedReceivedTwice");
    }

    private void addRestrictBackgroundWhitelist(int uid) throws Exception {
        runCommand("cmd netpolicy add restrict-background-whitelist " + uid);
        assertRestrictBackgroundWhitelist(uid, true);
    }

    private void removeRestrictBackgroundWhitelist(int uid) throws Exception {
        runCommand("cmd netpolicy remove restrict-background-whitelist " + uid);
        assertRestrictBackgroundWhitelist(uid, false);
    }

    private void assertRestrictBackgroundWhitelist(int uid, boolean expected) throws Exception {
        final int max_tries = 5;
        boolean actual = false;
        for (int i = 1; i <= max_tries; i++) {
            final String output = runCommand("cmd netpolicy list restrict-background-whitelist ");
            actual = output.contains(Integer.toString(uid));
            if (expected == actual) {
                return;
            }
            Log.v(TAG, "whitelist check for uid " + uid + " doesn't match yet (expected "
                    + expected + ", got " + actual + "); sleeping 1s before polling again");
            Thread.sleep(1000);
        }
        fail("whitelist check for uid " + uid + " failed: expected "
                + expected + ", got " + actual);
    }

    private void setWifiMeteredStatus(boolean metered) throws DeviceNotAvailableException {
        mWifiHelper.enableWifi();
        // TODO: if it's not guaranteed the device has wi-fi, we need to change the tests
        // to make the actual verification of restrictions optional.
        final String netId = mWifiHelper.getSSID();
        assertNotNull("null SSID", netId);
        assertFalse("empty SSID", netId.trim().isEmpty());

        Log.i(TAG, "Setting wi-fi network " + netId + " metered status to " + metered);
        final String setCommand = "cmd netpolicy set metered-network " + netId + " "+ metered;
        final String result = runCommand(setCommand);
        assertTrue("Command '" + setCommand + "' failed: " + result, result.trim().isEmpty());

        // Sanity check.
        final String newStatus = runCommand("cmd netpolicy get metered-network " + netId);
        assertEquals("Metered status of wi-fi network " + netId + " not set properly",
                newStatus.trim(), Boolean.toString(metered));
    }

    private void setRestrictBackground(boolean enabled) throws DeviceNotAvailableException {
        runCommand("cmd netpolicy set restrict-background " + enabled);
        final String output = runCommand("cmd netpolicy get restrict-background ").trim();
        final String expectedSuffix = enabled ? "enabled" : "disabled";
        // TODO: use MoreAsserts?
        assertTrue("output '" + output + "' should end with '" + expectedSuffix + "'",
                output.endsWith(expectedSuffix));
    }
}
