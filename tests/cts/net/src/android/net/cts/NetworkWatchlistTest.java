/*
 * Copyright (C) 2018 The Android Open Source Project
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

package android.net.cts;

import android.content.Context;
import android.net.ConnectivityManager;
import android.os.FileUtils;
import android.support.test.InstrumentationRegistry;
import android.test.AndroidTestCase;

import com.android.compatibility.common.util.ApiLevelUtil;
import com.android.compatibility.common.util.SystemUtil;

import org.junit.Assert;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Formatter;

public class NetworkWatchlistTest extends AndroidTestCase {

    private static final String TEST_WATCHLIST_XML = "assets/network_watchlist_config_for_test.xml";
    private static final String SDCARD_CONFIG_PATH =
            "/sdcard/network_watchlist_config_for_test.xml";
    private static final String TMP_CONFIG_PATH =
            "/data/local/tmp/network_watchlist_config_for_test.xml";
    // Generated from sha256sum network_watchlist_config_for_test.xml
    private static final String TEST_WATCHLIST_CONFIG_HASH =
            "B5FC4636994180D54E1E912F78178AB1D8BD2BE71D90CA9F5BBC3284E4D04ED4";

    private Context mContext;
    private boolean mHasFeature;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        mContext = getContext();
        mHasFeature = isAtLeastP();
        runCommand("rm " + SDCARD_CONFIG_PATH);
        runCommand("rm " + TMP_CONFIG_PATH);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        runCommand("rm " + SDCARD_CONFIG_PATH);
        runCommand("rm " + TMP_CONFIG_PATH);
    }

    private boolean isAtLeastP() throws Exception {
        // TODO: replace with ApiLevelUtil.isAtLeast(Build.VERSION_CODES.P) when the P API level
        // constant is defined.
        return ApiLevelUtil.getCodename().compareToIgnoreCase("P") >= 0;
    }

    /**
     * Test if ConnectivityManager.getNetworkWatchlistConfigHash() correctly
     * returns the hash of config we set.
     */
    public void testGetWatchlistConfigHash() throws Exception {
        if (!mHasFeature) {
            return;
        }
        // TODO: Test watchlist config does not exist case
        // Save test watchlist config to sdcard as app can't access /data/local/tmp
        saveResourceToFile(TEST_WATCHLIST_XML, SDCARD_CONFIG_PATH);
        // Copy test watchlist config from sdcard to /data/local/tmp as systerm service
        // can't access /sdcard
        runCommand("cp " + SDCARD_CONFIG_PATH + " " + TMP_CONFIG_PATH);
        // Set test watchlist config to system
        final String cmdResult = runCommand(
                "cmd network_watchlist set-test-config " + TMP_CONFIG_PATH).trim();
        assertTrue(cmdResult.contains("Success"));
        // Test if watchlist config hash value is correct
        ConnectivityManager connectivityManager =
                (ConnectivityManager) getContext().getSystemService(
                        Context.CONNECTIVITY_SERVICE);
        byte[] result = connectivityManager.getNetworkWatchlistConfigHash();
        Assert.assertEquals(TEST_WATCHLIST_CONFIG_HASH, byteArrayToHexString(result));
    }

    private static String byteArrayToHexString(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02X", b);
        }
        return formatter.toString();
    }

    private void saveResourceToFile(String res, String filePath) throws IOException {
        InputStream in = getClass().getClassLoader().getResourceAsStream(res);
        FileUtils.copyToFileOrThrow(in, new File(filePath));
    }

    private static String runCommand(String command) throws IOException {
        return SystemUtil.runShellCommand(InstrumentationRegistry.getInstrumentation(), command);
    }
}
