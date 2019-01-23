/*
 * Copyright (C) 2019 The Android Open Source Project
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

import static android.net.DnsResolver.CLASS_IN;
import static android.net.DnsResolver.TYPE_A;
import static android.net.DnsResolver.TYPE_AAAA;
import static android.net.DnsResolver.FLAG_NO_CACHE_LOOKUP;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DnsResolver;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkUtils;
import android.os.Handler;
import android.os.Looper;
import android.system.ErrnoException;
import android.test.AndroidTestCase;
import android.util.Log;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class DnsResolverTest extends AndroidTestCase {
    private static final String TAG = "DnsResolverTest";
    private static final char[] HEX_CHARS = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    private ConnectivityManager mCM;
    private Handler mHandler;
    private DnsResolver mDns;

    protected void setUp() throws Exception {
        super.setUp();
        mCM = (ConnectivityManager) getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        mHandler = new Handler(Looper.getMainLooper());
        mDns = DnsResolver.getInstance();
    }

    private static String bytesArrayToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; ++i) {
            int b = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_CHARS[b >>> 4];
            hexChars[i * 2 + 1] = HEX_CHARS[b & 0x0F];
        }
        return new String(hexChars);
    }

    private Network[] getTestableNetworks() {
        final ArrayList<Network> testableNetworks = new ArrayList<Network>();
        for (Network network : mCM.getAllNetworks()) {
            final NetworkCapabilities nc = mCM.getNetworkCapabilities(network);
            if (nc != null
                    && nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                    && nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                testableNetworks.add(network);
            }
        }

        assertTrue(
                "This test requires that at least one network be connected. " +
                "Please ensure that the device is connected to a network.",
                testableNetworks.size() >= 1);
        return testableNetworks.toArray(new Network[0]);
    }

    public void testInetAddressQuery() throws ErrnoException {
        for (Network network : getTestableNetworks()) {
            CountDownLatch latch = new CountDownLatch(1);
            final int TIMEOUT_MS = 5_000;
            final String dname = "www.google.com";

            mDns.query(network, dname, FLAG_NO_CACHE_LOOKUP, mHandler, answerList -> {
                    if (answerList.size() != 0) {
                        latch.countDown();
                        for (InetAddress addr : answerList) {
                            Log.e(TAG, "Reported addr:" + addr.toString());
                        }
                    }
                }
            );
            String msg = "InetAddress query " + dname + " but no valid answer after "
                    + TIMEOUT_MS + "ms.";
            try {
                assertTrue(msg, latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            } catch (InterruptedException e) {}
        }
    }

    public void testRawQuery() throws ErrnoException {
        for (Network network : getTestableNetworks()) {
            CountDownLatch latch = new CountDownLatch(1);
            final int TIMEOUT_MS = 5_000;
            final String dname = "www.google.com";

            mDns.query(network, dname, CLASS_IN, TYPE_AAAA, FLAG_NO_CACHE_LOOKUP, mHandler, answer -> {
                    if (answer != null) {
                        latch.countDown();
                        Log.e(TAG, "Reported blob:" + bytesArrayToHexString(answer));
                    }
                }
            );
            String msg = "Raw query " + dname + " but no valid answer after " + TIMEOUT_MS + "ms.";
            try {
                assertTrue(msg, latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            } catch (InterruptedException e) {}
        }
    }

    public void testRawQueryWithBlob() throws ErrnoException {
        for (Network network : getTestableNetworks()) {
            CountDownLatch latch = new CountDownLatch(1);
            final int TIMEOUT_MS = 5_000;
            final byte[] blob = new byte[] {
                    /* Header */
                    0x55, 0x66, /* Transaction ID */
                    0x01, 0x00, /* Flags */
                    0x00, 0x01, /* Questions */
                    0x00, 0x00, /* Answer RRs */
                    0x00, 0x00, /* Authority RRs */
                    0x00, 0x00, /* Additional RRs */
                    /* Queries */
                    0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6c, 0x65,
                    0x03, 0x63, 0x6f, 0x6d, 0x00, /* Name */
                    0x00, 0x01, /* Type */
                    0x00, 0x01  /* Class */
            };

            mDns.query(network, blob, FLAG_NO_CACHE_LOOKUP, mHandler, answer -> {
                    if (answer != null) {
                        latch.countDown();
                        Log.e(TAG, "Reported blob:" + bytesArrayToHexString(answer));
                    }
                }
            );
            String msg = "Raw query with blob " + bytesArrayToHexString(blob) +
                    " but no valid answer after " + TIMEOUT_MS + "ms.";
            try {
                assertTrue(msg, latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            } catch (InterruptedException e) {}
        }
    }
}
