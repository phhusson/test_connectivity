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

public class HostsideRestrictBackgroundNetworkTests extends HostsideNetworkTestCase {

    private static final String TEST_APP2_PKG = "com.android.cts.net.hostside.app2";
    private static final String TEST_APP2_APK = "CtsHostsideNetworkTestsApp2.apk";

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        uninstallPackage(TEST_APP2_PKG, false);
        installPackage(TEST_APP2_APK);

    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        uninstallPackage(TEST_APP2_PKG, true);
    }

    public void testDataSaverMode_disabled() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".DataSaverModeTest",
                "testGetRestrictBackgroundStatus_disabled");
    }

    public void testDataSaverMode_whitelisted() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".DataSaverModeTest",
                "testGetRestrictBackgroundStatus_whitelisted");
    }

    public void testDataSaverMode_enabled() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".DataSaverModeTest",
                "testGetRestrictBackgroundStatus_enabled");
    }

    public void testDataSaverMode_blacklisted() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".DataSaverModeTest",
                "testGetRestrictBackgroundStatus_blacklisted");
    }

    public void testDataSaverMode_reinstall() throws Exception {
        final int oldUid = getUid(TEST_PKG);
        testDataSaverMode_whitelisted();

        uninstallPackage(TEST_PKG, true);
        assertPackageUninstalled(TEST_PKG);
        assertRestrictBackgroundWhitelist(oldUid, false);

        installPackage(TEST_APK);
        final int newUid = getUid(TEST_PKG);
        assertRestrictBackgroundWhitelist(oldUid, false);
        assertRestrictBackgroundWhitelist(newUid, false);
    }

    public void testBatterySaverMode_disabled() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".BatterySaverModeTest",
                "testBackgroundNetworkAccess_disabled");
    }

    public void testBatterySaverMode_whitelisted() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".BatterySaverModeTest",
                "testBackgroundNetworkAccess_whitelisted");
    }

    public void testBatterySaverMode_enabled() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".BatterySaverModeTest",
                "testBackgroundNetworkAccess_enabled");
    }

    public void testBatterySaverMode_reinstall() throws Exception {
        testBatterySaverMode_whitelisted();

        uninstallPackage(TEST_PKG, true);
        assertPackageUninstalled(TEST_PKG);
        assertPowerSaveModeWhitelist(TEST_PKG, false);

        installPackage(TEST_APK);
        assertPowerSaveModeWhitelist(TEST_PKG, false);
    }

    public void testBatteryBatterySaverModeNonMeteredTest_disabled() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".BatterySaverModeNonMeteredTest",
                "testBackgroundNetworkAccess_disabled");
    }

    public void testBatteryBatterySaverModeNonMeteredTest_whitelisted() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".BatterySaverModeNonMeteredTest",
                "testBackgroundNetworkAccess_whitelisted");
    }

    public void testBatteryBatterySaverModeNonMeteredTest_enabled() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".BatterySaverModeNonMeteredTest",
                "testBackgroundNetworkAccess_enabled");
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

    private void assertPowerSaveModeWhitelist(String packageName, boolean expected)
            throws Exception {
        // TODO: currently the power-save mode is behaving like idle, but once it changes, we'll
        // need to use netpolicy for whitelisting
        assertDelayedCommand("dumpsys deviceidle whitelist =" + packageName,
                Boolean.toString(expected));
    }

    /**
     * Asserts the result of a command, wait and re-running it a couple times if necessary.
     */
    private void assertDelayedCommand(String command, String expectedResult)
            throws InterruptedException, DeviceNotAvailableException {
        final int maxTries = 5;
        for (int i = 1; i <= maxTries; i++) {
            final String result = runCommand(command).trim();
            if (result.equals(expectedResult)) return;
            Log.v(TAG, "Command '" + command + "' returned '" + result + " instead of '"
                    + expectedResult + "' on attempt #; sleeping 1s before polling again");
            Thread.sleep(1000);
        }
        fail("Command '" + command + "' did not return '" + expectedResult + "' after " + maxTries
                + " attempts");
    }
}
