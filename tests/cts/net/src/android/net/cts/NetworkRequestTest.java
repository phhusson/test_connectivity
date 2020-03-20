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

import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
import static android.net.NetworkCapabilities.NET_CAPABILITY_MMS;
import static android.net.NetworkCapabilities.TRANSPORT_BLUETOOTH;
import static android.net.NetworkCapabilities.TRANSPORT_CELLULAR;
import static android.net.NetworkCapabilities.TRANSPORT_VPN;
import static android.net.NetworkCapabilities.TRANSPORT_WIFI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.net.MacAddress;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.NetworkSpecifier;
import android.net.wifi.WifiNetworkSpecifier;
import android.os.Build;
import android.os.Process;
import android.os.PatternMatcher;

import androidx.test.runner.AndroidJUnit4;

import com.android.testutils.DevSdkIgnoreRule;
import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class NetworkRequestTest {
    @Rule
    public final DevSdkIgnoreRule ignoreRule = new DevSdkIgnoreRule();

    private static final String TEST_SSID = "TestSSID";
    private static final String OTHER_SSID = "OtherSSID";
    private static final int TEST_UID = 2097;
    private static final String TEST_PACKAGE_NAME = "test.package.name";
    private static final MacAddress ARBITRARY_ADDRESS = MacAddress.fromString("3:5:8:12:9:2");

    @Test
    public void testCapabilities() {
        assertTrue(new NetworkRequest.Builder().addCapability(NET_CAPABILITY_MMS).build()
                .hasCapability(NET_CAPABILITY_MMS));
        assertFalse(new NetworkRequest.Builder().removeCapability(NET_CAPABILITY_MMS).build()
                .hasCapability(NET_CAPABILITY_MMS));

        final NetworkRequest nr = new NetworkRequest.Builder().clearCapabilities().build();
        // Verify request has no capabilities
        verifyNoCapabilities(nr);
    }

    private void verifyNoCapabilities(NetworkRequest nr) {
        // NetworkCapabilities.mNetworkCapabilities is defined as type long
        final int MAX_POSSIBLE_CAPABILITY = Long.SIZE;
        for(int bit = 0; bit < MAX_POSSIBLE_CAPABILITY; bit++) {
            assertFalse(nr.hasCapability(bit));
        }
    }

    @Test
    public void testTransports() {
        assertTrue(new NetworkRequest.Builder().addTransportType(TRANSPORT_BLUETOOTH).build()
                .hasTransport(TRANSPORT_BLUETOOTH));
        assertFalse(new NetworkRequest.Builder().removeTransportType(TRANSPORT_BLUETOOTH).build()
                .hasTransport(TRANSPORT_BLUETOOTH));
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.Q)
    public void testSpecifier() {
        assertNull(new NetworkRequest.Builder().build().getNetworkSpecifier());
        final WifiNetworkSpecifier specifier = new WifiNetworkSpecifier.Builder()
                .setSsidPattern(new PatternMatcher(TEST_SSID, PatternMatcher.PATTERN_LITERAL))
                .setBssidPattern(ARBITRARY_ADDRESS, ARBITRARY_ADDRESS)
                .build();
        final NetworkSpecifier obtainedSpecifier = new NetworkRequest.Builder()
                .addTransportType(TRANSPORT_WIFI)
                .setNetworkSpecifier(specifier)
                .build()
                .getNetworkSpecifier();
        assertEquals(obtainedSpecifier, specifier);

        assertNull(new NetworkRequest.Builder()
                .clearCapabilities()
                .build()
                .getNetworkSpecifier());
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.Q)
    public void testRequestorPackageName() {
        assertNull(new NetworkRequest.Builder().build().getRequestorPackageName());
        final String pkgName = "android.net.test";
        final NetworkCapabilities nc = new NetworkCapabilities.Builder()
                .setRequestorPackageName(pkgName)
                .build();
        final NetworkRequest nr = new NetworkRequest.Builder()
                .setCapabilities(nc)
                .build();
        assertEquals(pkgName, nr.getRequestorPackageName());
        assertNull(new NetworkRequest.Builder()
                .clearCapabilities()
                .build()
                .getRequestorPackageName());
    }

    @Test
    @IgnoreUpTo(Build.VERSION_CODES.Q)
    public void testCanBeSatisfiedBy() {
        final WifiNetworkSpecifier specifier1 = new WifiNetworkSpecifier.Builder()
                .setSsidPattern(new PatternMatcher(TEST_SSID, PatternMatcher.PATTERN_LITERAL))
                .setBssidPattern(ARBITRARY_ADDRESS, ARBITRARY_ADDRESS)
                .build();
        final WifiNetworkSpecifier specifier2 = new WifiNetworkSpecifier.Builder()
                .setSsidPattern(new PatternMatcher(OTHER_SSID, PatternMatcher.PATTERN_LITERAL))
                .setBssidPattern(ARBITRARY_ADDRESS, ARBITRARY_ADDRESS)
                .build();
        final NetworkCapabilities cap = new NetworkCapabilities()
                .addTransportType(TRANSPORT_WIFI)
                .addCapability(NET_CAPABILITY_INTERNET);
        final NetworkCapabilities capWithSp =
                new NetworkCapabilities(cap).setNetworkSpecifier(specifier1);
        final NetworkCapabilities cellCap = new NetworkCapabilities()
                .addTransportType(TRANSPORT_CELLULAR)
                .addCapability(NET_CAPABILITY_MMS)
                .addCapability(NET_CAPABILITY_INTERNET);
        final NetworkRequest request = new NetworkRequest.Builder()
                .addTransportType(TRANSPORT_WIFI)
                .addCapability(NET_CAPABILITY_INTERNET)
                .setNetworkSpecifier(specifier1)
                .build();
        assertFalse(request.canBeSatisfiedBy(null));
        assertFalse(request.canBeSatisfiedBy(new NetworkCapabilities()));
        assertTrue(request.canBeSatisfiedBy(cap));
        assertTrue(request.canBeSatisfiedBy(
                new NetworkCapabilities(cap).addTransportType(TRANSPORT_VPN)));
        assertTrue(request.canBeSatisfiedBy(capWithSp));
        assertFalse(request.canBeSatisfiedBy(
                new NetworkCapabilities(cap).setNetworkSpecifier(specifier2)));
        assertFalse(request.canBeSatisfiedBy(cellCap));
        assertEquals(request.canBeSatisfiedBy(capWithSp),
                new NetworkCapabilities(capWithSp).satisfiedByNetworkCapabilities(capWithSp));
    }

    @Test @IgnoreUpTo(Build.VERSION_CODES.Q)
    public void testRequestorUid() {
        final NetworkCapabilities nc = new NetworkCapabilities();
        // Verify default value is INVALID_UID
        assertEquals(Process.INVALID_UID, new NetworkRequest.Builder()
                 .setCapabilities(nc).build().getRequestorUid());

        nc.setRequestorUid(1314);
        final NetworkRequest nr = new NetworkRequest.Builder().setCapabilities(nc).build();
        assertEquals(1314, nr.getRequestorUid());

        assertEquals(Process.INVALID_UID, new NetworkRequest.Builder()
                .clearCapabilities().build().getRequestorUid());
    }
}
