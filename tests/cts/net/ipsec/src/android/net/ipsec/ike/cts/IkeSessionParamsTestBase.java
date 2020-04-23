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

package android.net.ipsec.ike.cts;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.Network;
import android.net.TestNetworkInterface;
import android.net.TestNetworkManager;
import android.net.ipsec.ike.cts.TestNetworkUtils.TestNetworkCallback;
import android.os.Binder;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.platform.test.annotations.AppModeFull;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
@AppModeFull(reason = "MANAGE_TEST_NETWORKS permission can't be granted to instant apps")
abstract class IkeSessionParamsTestBase extends IkeTestBase {
    // Static state to reduce setup/teardown
    static ConnectivityManager sCM;
    static TestNetworkManager sTNM;
    static ParcelFileDescriptor sTunFd;
    static TestNetworkCallback sTunNetworkCallback;
    static Network sTunNetwork;

    static Context sContext = InstrumentationRegistry.getContext();
    static IBinder sBinder = new Binder();

    // This method is guaranteed to run in subclasses and will run before subclasses' @BeforeClass
    // methods.
    @BeforeClass
    public static void setUpTestNetworkBeforeClass() throws Exception {
        InstrumentationRegistry.getInstrumentation()
                .getUiAutomation()
                .adoptShellPermissionIdentity();
        sCM = (ConnectivityManager) sContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        sTNM = (TestNetworkManager) sContext.getSystemService(Context.TEST_NETWORK_SERVICE);

        TestNetworkInterface testIface =
                sTNM.createTunInterface(
                        new LinkAddress[] {new LinkAddress(IPV4_ADDRESS_LOCAL, IP4_PREFIX_LEN)});

        sTunFd = testIface.getFileDescriptor();
        sTunNetworkCallback =
                TestNetworkUtils.setupAndGetTestNetwork(
                        sCM, sTNM, testIface.getInterfaceName(), sBinder);
        sTunNetwork = sTunNetworkCallback.getNetworkBlocking();
    }

    // This method is guaranteed to run in subclasses and will run after subclasses' @AfterClass
    // methods.
    @AfterClass
    public static void tearDownTestNetworkAfterClass() throws Exception {
        sCM.unregisterNetworkCallback(sTunNetworkCallback);

        sTNM.teardownTestNetwork(sTunNetwork);
        sTunFd.close();

        InstrumentationRegistry.getInstrumentation()
                .getUiAutomation()
                .dropShellPermissionIdentity();
    }
}
