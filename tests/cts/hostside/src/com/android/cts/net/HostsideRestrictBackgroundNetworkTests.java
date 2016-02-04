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

import com.android.cts.migration.MigrationHelper;
import com.android.ddmlib.Log;
import com.android.ddmlib.testrunner.RemoteAndroidTestRunner;
import com.android.ddmlib.testrunner.TestIdentifier;
import com.android.ddmlib.testrunner.TestResult;
import com.android.ddmlib.testrunner.TestResult.TestStatus;
import com.android.ddmlib.testrunner.TestRunResult;
import com.android.tradefed.build.IBuildInfo;
import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.result.CollectingTestListener;
import com.android.tradefed.testtype.DeviceTestCase;
import com.android.tradefed.testtype.IAbi;
import com.android.tradefed.testtype.IAbiReceiver;
import com.android.tradefed.testtype.IBuildReceiver;

import java.io.FileNotFoundException;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HostsideRestrictBackgroundNetworkTests extends DeviceTestCase implements IAbiReceiver,
        IBuildReceiver {
    private static final boolean DEBUG = false;
    private static final String TAG = "HostsideNetworkTests";
    private static final String TEST_PKG = "com.android.cts.net.hostside";
    private static final String TEST_APK = "CtsHostsideNetworkTestsApp.apk";

    private static final String TEST_APP2_PKG = "com.android.cts.net.hostside.app2";
    private static final String TEST_APP2_APK = "CtsHostsideNetworkTestsApp2.apk";

    private IAbi mAbi;
    private IBuildInfo mCtsBuild;

    @Override
    public void setAbi(IAbi abi) {
        mAbi = abi;
    }

    @Override
    public void setBuild(IBuildInfo buildInfo) {
        mCtsBuild = buildInfo;
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        assertNotNull(mAbi);
        assertNotNull(mCtsBuild);

        setRestrictBackground(false);

        uninstallPackage(TEST_PKG, false);
        installPackage(TEST_APK);
        // TODO: split this class into HostsideVpnTests and HostsideConnectivityManagerTests so
        // the former don't need to unnecessarily install app2.
        uninstallPackage(TEST_APP2_PKG, false);
        installPackage(TEST_APP2_APK);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        uninstallPackage(TEST_PKG, true);
        uninstallPackage(TEST_APP2_PKG, true);

        setRestrictBackground(false);
    }

    public void testVpn() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".VpnTest");
    }

    public void testConnectivityManager_getRestrictBackgroundStatus_disabled() throws Exception {
        startBroadcastReceiverService();
        final int uid = getUid(TEST_PKG);

        removeRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundStatusDisabled();
        assertRestrictBackgroundChangedReceivedOnce();

        // Sanity check: make sure status is always disabled, never whitelisted
        addRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundStatusDisabled();
        assertRestrictBackgroundChangedReceivedTwice();
    }

    public void testConnectivityManager_getRestrictBackgroundStatus_whitelisted() throws Exception {
        startBroadcastReceiverService();
        final int uid = getUid(TEST_PKG);

        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceivedOnce();

        addRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundStatusWhitelisted();
        assertRestrictBackgroundChangedReceivedTwice();
    }

    public void testConnectivityManager_getRestrictBackgroundStatus_enabled() throws Exception {
        startBroadcastReceiverService();
        final int uid = getUid(TEST_PKG);

        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceivedOnce();

        removeRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundStatusEnabled();
        assertRestrictBackgroundChangedReceivedTwice();
    }

    public void testConnectivityManager_getRestrictBackgroundStatus_uninstall() throws Exception {
        final int uid = getUid(TEST_PKG);

        addRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundWhitelist(uid, true);

        uninstallPackage(TEST_PKG, true);
        assertPackageUninstalled(TEST_PKG);
        assertRestrictBackgroundWhitelist(uid, false);

        installPackage(TEST_APK);
        final int newUid = getUid(TEST_PKG);
        assertRestrictBackgroundWhitelist(uid, false);
        assertRestrictBackgroundWhitelist(newUid, false);
    }

    private void installPackage(String apk) throws DeviceNotAvailableException,
            FileNotFoundException {
        assertNull(getDevice().installPackage(
                MigrationHelper.getTestFile(mCtsBuild, apk), false));
    }

    private void uninstallPackage(String packageName, boolean shouldSucceed)
            throws DeviceNotAvailableException {
        final String result = getDevice().uninstallPackage(packageName);
        if (shouldSucceed) {
            assertNull("uninstallPackage(" + packageName + ") failed: " + result, result);
        }
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

    private void assertPackageUninstalled(String packageName) throws Exception {
        final String command = "cmd package list packages " + packageName;
        final int max_tries = 5;
        for (int i = 1; i <= max_tries; i++) {
            final String result = runCommand(command);
            if (result.trim().isEmpty()) {
                return;
            }
            // 'list packages' filters by substring, so we need to iterate with the results
            // and check one by one, otherwise 'com.android.cts.net.hostside' could return
            // 'com.android.cts.net.hostside.app2'
            boolean found = false;
            for (String line : result.split("[\\r\\n]+")) {
                if (line.endsWith(packageName)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return;
            }
            i++;
            Log.v(TAG, "Package " + packageName + " not uninstalled yet (" + result
                    + "); sleeping 1s before polling again");
            Thread.sleep(1000);
        }
        fail("Package '" + packageName + "' not uinstalled after " + max_tries + " seconds");
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

    public void runDeviceTests(String packageName, String testClassName)
            throws DeviceNotAvailableException {
        runDeviceTests(packageName, testClassName, null);
    }

    public void runDeviceTests(String packageName, String testClassName, String methodName)
            throws DeviceNotAvailableException {
        RemoteAndroidTestRunner testRunner = new RemoteAndroidTestRunner(packageName,
                "android.support.test.runner.AndroidJUnitRunner", getDevice().getIDevice());

        if (testClassName != null) {
            if (methodName != null) {
                testRunner.setMethodName(testClassName, methodName);
            } else {
                testRunner.setClassName(testClassName);
            }
        }

        final CollectingTestListener listener = new CollectingTestListener();
        getDevice().runInstrumentationTests(testRunner, listener);

        final TestRunResult result = listener.getCurrentRunResults();
        if (result.isRunFailure()) {
            throw new AssertionError("Failed to successfully run device tests for "
                    + result.getName() + ": " + result.getRunFailureMessage());
        }

        if (result.hasFailedTests()) {
            // build a meaningful error message
            StringBuilder errorBuilder = new StringBuilder("on-device tests failed:\n");
            for (Map.Entry<TestIdentifier, TestResult> resultEntry :
                result.getTestResults().entrySet()) {
                if (!resultEntry.getValue().getStatus().equals(TestStatus.PASSED)) {
                    errorBuilder.append(resultEntry.getKey().toString());
                    errorBuilder.append(":\n");
                    errorBuilder.append(resultEntry.getValue().getStackTrace());
                }
            }
            throw new AssertionError(errorBuilder.toString());
        }
    }

    private static final Pattern UID_PATTERN =
            Pattern.compile(".*userId=([0-9]+)$", Pattern.MULTILINE);

    private int getUid(String packageName) throws DeviceNotAvailableException {
        final String output = runCommand("dumpsys package " + packageName);
        final Matcher matcher = UID_PATTERN.matcher(output);
        while (matcher.find()) {
            final String match = matcher.group(1);
            return Integer.parseInt(match);
        }
        throw new RuntimeException("Did not find regexp '" + UID_PATTERN + "' on adb output\n"
                + output);
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

    private void setRestrictBackground(boolean enabled) throws DeviceNotAvailableException {
        runCommand("cmd netpolicy set restrict-background " + enabled);
        final String output = runCommand("cmd netpolicy get restrict-background ").trim();
        final String expectedSuffix = enabled ? "enabled" : "disabled";
        // TODO: use MoreAsserts?
        assertTrue("output '" + output + "' should end with '" + expectedSuffix + "'",
                output.endsWith(expectedSuffix));
    }

    private String runCommand(String command) throws DeviceNotAvailableException {
        Log.d(TAG, "Command: '" + command + "'");
        final String output = getDevice().executeShellCommand(command);
        if (DEBUG) Log.v(TAG, "Output: " + output.trim());
        return output;
    }
}
