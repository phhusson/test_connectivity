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

public class DataSaverModeTest extends AbstractRestrictBackgroundNetworkTestCase {

    @Override
    public void setUp() throws Exception {
        super.setUp();

        setMeteredNetwork();
        setRestrictBackground(false);
        registerApp2BroadcastReceiver();
   }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        setRestrictBackground(false);
    }

    public void testGetRestrictBackgroundStatus_disabled() throws Exception {
        removeRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_DISABLED);
        assertRestrictBackgroundChangedReceived(0);

        // Sanity check: make sure status is always disabled, never whitelisted
        addRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_DISABLED);
        assertRestrictBackgroundChangedReceived(0);
    }

    public void testGetRestrictBackgroundStatus_whitelisted() throws Exception {
        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceived(1);

        addRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_WHITELISTED);
        assertRestrictBackgroundChangedReceived(2);
    }

    public void testGetRestrictBackgroundStatus_enabled() throws Exception {
        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceived(1);

        removeRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);
        assertRestrictBackgroundChangedReceived(1);
    }

    public void testGetRestrictBackgroundStatus_blacklisted() throws Exception {
        addRestrictBackgroundBlacklist(mUid);
        assertRestrictBackgroundChangedReceived(1);

        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);

        // TODO: currently whitelist is prevailing, hence remaining of the test below is disabled
        if (true) return;

        // Make sure blacklist prevails over whitelist.
        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceived(2);
        addRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);

        // Check status after removing blacklist.
        removeRestrictBackgroundBlacklist(mUid);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_WHITELISTED);
        assertRestrictBackgroundChangedReceived(3);
        setRestrictBackground(false);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_DISABLED);
        assertRestrictBackgroundChangedReceived(4);
    }
}
