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

/*
 * TODO: need to add more scenarios:
 * - test access on foreground app
 * - test access on foreground service app
 * - make sure it works when app is on foreground and state is transitioned:
 *   - data saver is enabled
 *   - app is added/removed to blacklist
 *
 */
public class DataSaverModeTest extends AbstractRestrictBackgroundNetworkTestCase {

    private static final String[] REQUIRED_WHITELISTED_PACKAGES = {
        "com.android.providers.downloads"
    };

    @Override
    public void setUp() throws Exception {
        super.setUp();

        setMeteredNetwork();
        setRestrictBackground(false);
        registerBroadcastReceiver();
   }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        try {
            resetMeteredNetwork();
        } finally {
            setRestrictBackground(false);
        }
    }

    public void testGetRestrictBackgroundStatus_disabled() throws Exception {
        removeRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundChangedReceived(0);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_DISABLED);

        // Sanity check: make sure status is always disabled, never whitelisted
        addRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundChangedReceived(0);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_DISABLED);
    }

    public void testGetRestrictBackgroundStatus_whitelisted() throws Exception {
        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceived(1);

        addRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundChangedReceived(2);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_WHITELISTED);

        removeRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundChangedReceived(3);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);
   }

    public void testGetRestrictBackgroundStatus_enabled() throws Exception {
        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceived(1);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);

        removeRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundChangedReceived(1);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);

        // Make sure app is allowed if running a foreground service.
        assertBackgroundNetworkAccess(false);
        startForegroundService();
        assertForegroundServiceState();
        assertBackgroundNetworkAccess(true);
    }

    public void testGetRestrictBackgroundStatus_blacklisted() throws Exception {
        addRestrictBackgroundBlacklist(mUid);
        assertRestrictBackgroundChangedReceived(1);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);

        // Make sure blacklist prevails over whitelist.
        setRestrictBackground(true);
        assertRestrictBackgroundChangedReceived(2);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);
        addRestrictBackgroundWhitelist(mUid);
        assertRestrictBackgroundChangedReceived(3);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_ENABLED);

        // Check status after removing blacklist.
        removeRestrictBackgroundBlacklist(mUid);
        assertRestrictBackgroundChangedReceived(4);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_WHITELISTED);
        setRestrictBackground(false);
        assertRestrictBackgroundChangedReceived(5);
        assertRestrictBackgroundStatus(RESTRICT_BACKGROUND_STATUS_DISABLED);
    }

    public void testGetRestrictBackgroundStatus_requiredWhitelistedPackages() throws Exception {
        final StringBuilder error = new StringBuilder();
        for (String packageName : REQUIRED_WHITELISTED_PACKAGES) {
            int uid = -1;
            try {
                uid = getUid(packageName);
                assertRestrictBackgroundWhitelist(uid, true);
            } catch (Throwable t) {
                error.append("\nFailed for '").append(packageName).append("'");
                if (uid > 0) {
                    error.append(" (uid ").append(uid).append(")");
                }
                error.append(": ").append(t).append("\n");
            }
        }
        if (error.length() > 0) {
            fail(error.toString());
        }
    }
}
