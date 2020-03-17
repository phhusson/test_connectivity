/*
 * Copyright (C) 2020 The Android Open Source Project
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

package android.net.wifi.cts;

import static org.junit.Assert.assertNotNull;

import android.net.wifi.SoftApConfiguration;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiMigration;
import android.test.AndroidTestCase;

import java.util.Arrays;
import java.util.List;

public class WifiMigrationTest extends AndroidTestCase {
    private static final String TEST_SSID_UNQUOTED = "testSsid1";

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
    }

    @Override
    protected void tearDown() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            super.tearDown();
            return;
        }
        super.tearDown();
    }

    /**
     * Tests {@link android.net.wifi.WifiMigration.ConfigStoreMigrationData} class.
     */
    public void testWifiMigrationSettingsDataBuilder() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        WifiMigration.SettingsMigrationData migrationData =
                new WifiMigration.SettingsMigrationData.Builder()
                        .setScanAlwaysAvailable(true)
                        .setP2pFactoryResetPending(true)
                        .setScanThrottleEnabled(true)
                        .setSoftApTimeoutEnabled(true)
                        .setWakeUpEnabled(true)
                        .setVerboseLoggingEnabled(true)
                        .setP2pDeviceName(TEST_SSID_UNQUOTED)
                        .build();

        assertNotNull(migrationData);
        assertTrue(migrationData.isScanAlwaysAvailable());
        assertTrue(migrationData.isP2pFactoryResetPending());
        assertTrue(migrationData.isScanThrottleEnabled());
        assertTrue(migrationData.isSoftApTimeoutEnabled());
        assertTrue(migrationData.isWakeUpEnabled());
        assertTrue(migrationData.isVerboseLoggingEnabled());
        assertEquals(TEST_SSID_UNQUOTED, migrationData.getP2pDeviceName());
    }
}
