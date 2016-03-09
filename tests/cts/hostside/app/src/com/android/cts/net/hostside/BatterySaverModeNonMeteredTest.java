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

//TODO: move this and BatterySaverModeTest's logic into a common superclass
public class BatterySaverModeNonMeteredTest extends AbstractRestrictBackgroundNetworkTestCase {

    @Override
    public void setUp() throws Exception {
        super.setUp();

        setPowerSaveMode(false);
        assertPowerSaveModeWhitelist(TEST_APP2_PKG, false); // Sanity check
        registerApp2BroadcastReceiver();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        setPowerSaveMode(false);
    }

    public void testBackgroundNetworkAccess_enabled() throws Exception {
        setPowerSaveMode(true);
        assertBackgroundNetworkAccess(false);
    }

    public void testBackgroundNetworkAccess_whitelisted() throws Exception {
        setPowerSaveMode(true);
        assertBackgroundNetworkAccess(false);
        addPowerSaveModeWhitelist(TEST_APP2_PKG);
        assertBackgroundNetworkAccess(true);
        removePowerSaveModeWhitelist(TEST_APP2_PKG);
        assertBackgroundNetworkAccess(false);
    }

    public void testBackgroundNetworkAccess_disabled() throws Exception {
        setPowerSaveMode(false);
        assertBackgroundNetworkAccess(true);
    }
}
