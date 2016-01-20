/*
 * Copyright (C) 2014 The Android Open Source Project
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

public class HostsideNetworkTests extends DeviceTestCase implements IAbiReceiver, IBuildReceiver {
    private static final boolean DEBUG = false;
    private static final String TAG = "HostsideNetworkTests";
    private static final String TEST_PKG = "com.android.cts.net.hostside";
    private static final String TEST_APK = "CtsHostsideNetworkTestsApp.apk";

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
        uninstallTestPackage(false);
        installTestPackage();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        uninstallTestPackage(false);
        setRestrictBackground(false);
    }

    public void testVpn() throws Exception {
        runDeviceTests(TEST_PKG, TEST_PKG + ".VpnTest");
    }

    public void testConnectivityManager_getRestrictBackgroundStatus_disabled() throws Exception {
        final int uid = getUid(TEST_PKG);
        removeRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundStatusDisabled();
        // Sanity check: make sure status is always disabled, never whitelisted
        addRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundStatusDisabled();
    }

    public void testConnectivityManager_getRestrictBackgroundStatus_whitelisted() throws Exception {
        final int uid = getUid(TEST_PKG);
        setRestrictBackground(true);
        addRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundStatusWhitelisted();
    }

    public void testConnectivityManager_getRestrictBackgroundStatus_enabled() throws Exception {
        final int uid = getUid(TEST_PKG);
        setRestrictBackground(true);
        removeRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundStatusEnabled();
    }

    public void testConnectivityManager_getRestrictBackgroundStatus_uninstall() throws Exception {
        final int uid = getUid(TEST_PKG);

        addRestrictBackgroundWhitelist(uid);
        assertRestrictBackgroundWhitelist(uid, true);

        uninstallTestPackage(true);
        assertPackageUninstalled(TEST_PKG);
        assertRestrictBackgroundWhitelist(uid, false);

        installTestPackage();
        final int newUid = getUid(TEST_PKG);
        assertRestrictBackgroundWhitelist(uid, false);
        assertRestrictBackgroundWhitelist(newUid, false);
    }

    private void installTestPackage() throws DeviceNotAvailableException, FileNotFoundException {
        assertNull(getDevice().installPackage(
                MigrationHelper.getTestFile(mCtsBuild, TEST_APK), false));
    }

    private void uninstallTestPackage(boolean shouldSucceed) throws DeviceNotAvailableException {
        final String result = getDevice().uninstallPackage(TEST_PKG);
        if (shouldSucceed) {
            assertNull("uninstallPackage failed: " + result, result);
        }
    }

    private void assertPackageUninstalled(String packageName) throws DeviceNotAvailableException {
        final String command = "cmd package list packages -f " + packageName;
        final int max_tries = 5;
        for (int i = 1; i <= max_tries; i++) {
            final String result = runCommand(command);
            if (result.trim().isEmpty()) {
                return;
            }
            i++;
            Log.v(TAG, "Package " + packageName + " not uninstalled yet (" + result
                    + "); sleeping 1s before polling again");
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
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

    public void runDeviceTests(String packageName, String testClassName)
            throws DeviceNotAvailableException {
        runDeviceTests(packageName, testClassName, null);
    }

    public void runDeviceTests(String packageName, String testClassName, String methodName)
            throws DeviceNotAvailableException {
        RemoteAndroidTestRunner testRunner = new RemoteAndroidTestRunner(packageName,
                "android.support.test.runner.AndroidJUnitRunner", getDevice().getIDevice());

        if (testClassName != null) {
            // TODO: figure out why testRunner.setMethodName() / testRunner.setClassName() doesn't
            // work
            final StringBuilder runOptions = new StringBuilder("-e class ").append(testClassName);
            if (methodName != null) {
                runOptions.append('#').append(methodName);
            }
            Log.i(TAG, "Setting runOptions() as " + runOptions);
            testRunner.setRunOptions(runOptions.toString());
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

    private void addRestrictBackgroundWhitelist(int uid) throws DeviceNotAvailableException {
        runCommand("cmd netpolicy add restrict-background-whitelist " + uid);
        assertRestrictBackgroundWhitelist(uid, true);
    }

    private void removeRestrictBackgroundWhitelist(int uid) throws DeviceNotAvailableException {
        runCommand("cmd netpolicy remove restrict-background-whitelist " + uid);
        assertRestrictBackgroundWhitelist(uid, false);
    }

    private void assertRestrictBackgroundWhitelist(int uid, boolean expected)
            throws DeviceNotAvailableException {
        final String output = runCommand("cmd netpolicy list restrict-background-whitelist ");
        // TODO: use MoreAsserts
        if (expected) {
            assertTrue("Did not find uid '" + uid + "' on '" + output + "'",
                    output.contains(Integer.toString(uid)));
        } else {
            assertFalse("Found uid '" + uid + "' on '" + output + "'",
                    output.contains(Integer.toString(uid)));
        }
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
