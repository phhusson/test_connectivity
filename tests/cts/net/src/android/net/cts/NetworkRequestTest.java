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

import static android.net.NetworkCapabilities.NET_CAPABILITY_MMS;
import static android.net.NetworkCapabilities.TRANSPORT_BLUETOOTH;

import android.net.NetworkRequest;
import android.test.AndroidTestCase;

public class NetworkRequestTest extends AndroidTestCase {
    public void testCapabilities() {
        assertTrue(new NetworkRequest.Builder().addCapability(NET_CAPABILITY_MMS).build()
                .hasCapability(NET_CAPABILITY_MMS));
        assertFalse(new NetworkRequest.Builder().removeCapability(NET_CAPABILITY_MMS).build()
                .hasCapability(NET_CAPABILITY_MMS));
    }

    public void testUnwantedCapabilities() {
        assertTrue(new NetworkRequest.Builder()
                .addUnwantedCapability(NET_CAPABILITY_MMS)
                .build()
                .hasUnwantedCapability(NET_CAPABILITY_MMS));
        assertFalse(new NetworkRequest.Builder()
                .removeCapability(NET_CAPABILITY_MMS)
                .build()
                .hasCapability(NET_CAPABILITY_MMS));
    }

    public void testCapabilityMutualExclusivity() {
        NetworkRequest.Builder reqBuilder = new NetworkRequest.Builder()
                .addCapability(NET_CAPABILITY_MMS);

        assertTrue(reqBuilder.build().hasCapability(NET_CAPABILITY_MMS));
        assertFalse(reqBuilder.build().hasUnwantedCapability(NET_CAPABILITY_MMS));

        // Move capability to unwanted list
        reqBuilder.addUnwantedCapability(NET_CAPABILITY_MMS);
        assertFalse(reqBuilder.build().hasCapability(NET_CAPABILITY_MMS));
        assertTrue(reqBuilder.build().hasUnwantedCapability(NET_CAPABILITY_MMS));

        // Move it back to the list of capabilities
        reqBuilder.addCapability(NET_CAPABILITY_MMS);
        assertTrue(reqBuilder.build().hasCapability(NET_CAPABILITY_MMS));
        assertFalse(reqBuilder.build().hasUnwantedCapability(NET_CAPABILITY_MMS));
    }

    public void testTransports() {
        assertTrue(new NetworkRequest.Builder().addTransportType(TRANSPORT_BLUETOOTH).build()
                .hasTransport(TRANSPORT_BLUETOOTH));
        assertFalse(new NetworkRequest.Builder().removeTransportType(TRANSPORT_BLUETOOTH).build()
                .hasTransport(TRANSPORT_BLUETOOTH));
    }
}
