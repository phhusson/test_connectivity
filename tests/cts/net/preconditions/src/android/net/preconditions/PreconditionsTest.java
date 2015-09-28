/*
 * Copyright (C) 2015 The Android Open Source Project
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
package android.net.preconditions;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.test.AndroidTestCase;

import com.android.compatibility.common.preconditions.WifiHelper;

/**
 * A test to verify that device-side preconditions are met for the net module of CTS
 */
public class PreconditionsTest extends AndroidTestCase {

    /**
     * Test if device is connected to WiFi
     * @throws Exception
     */
    public void testWifiConnected() throws Exception {
        assertTrue("Device must have active network connection",
                WifiHelper.isWifiConnected(this.getContext()));
    }

}
