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

    public void testGetRestrictBackgroundStatus_disabled() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".DataSaverModeTest",
                "testGetRestrictBackgroundStatus_disabled");
    }

    public void testGetRestrictBackgroundStatus_whitelisted() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".DataSaverModeTest",
                "testGetRestrictBackgroundStatus_whitelisted");
    }

    public void testGetRestrictBackgroundStatus_enabled() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".DataSaverModeTest",
                "testGetRestrictBackgroundStatus_enabled");
    }

    public void testGetRestrictBackgroundStatus_uninstall() throws Exception {
        final int oldUid = getUid(TEST_PKG);
        testGetRestrictBackgroundStatus_whitelisted();

        uninstallPackage(TEST_PKG, true);
        assertPackageUninstalled(TEST_PKG);
        assertRestrictBackgroundWhitelist(oldUid, false);

        installPackage(TEST_APK);
        final int newUid = getUid(TEST_PKG);
        assertRestrictBackgroundWhitelist(oldUid, false);
        assertRestrictBackgroundWhitelist(newUid, false);
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
}
