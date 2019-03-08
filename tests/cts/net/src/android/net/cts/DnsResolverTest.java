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
import static android.net.DnsResolver.FLAG_NO_CACHE_LOOKUP;
import static android.net.DnsResolver.TYPE_AAAA;

import android.annotation.NonNull;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.DnsPacket;
import android.net.DnsResolver;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Handler;
import android.os.Looper;
import android.system.ErrnoException;
import android.test.AndroidTestCase;
import android.util.Log;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class DnsResolverTest extends AndroidTestCase {
    private static final String TAG = "DnsResolverTest";
    private static final char[] HEX_CHARS = {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    static final int TIMEOUT_MS = 12_000;

    private ConnectivityManager mCM;
    private Handler mHandler;
    private DnsResolver mDns;

    protected void setUp() throws Exception {
        super.setUp();
        mCM = (ConnectivityManager) getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        mHandler = new Handler(Looper.getMainLooper());
        mDns = DnsResolver.getInstance();
    }

    private static String byteArrayToHexString(byte[] bytes) {
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
        final String dname = "www.google.com";
        final String msg = "InetAddress query " + dname;
        for (Network network : getTestableNetworks()) {
            final CountDownLatch latch = new CountDownLatch(1);
            final AtomicReference<List<InetAddress>> answers = new AtomicReference<>();

            mDns.query(network, dname, FLAG_NO_CACHE_LOOKUP, mHandler, answerList -> {
                        answers.set(answerList);
                        for (InetAddress addr : answerList) {
                            Log.d(TAG, "Reported addr:" + addr.toString());
                        }
                        latch.countDown();
                    }
            );
            try {
                assertTrue(msg + " but no valid answer after " + TIMEOUT_MS + "ms.",
                        latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
                assertGreaterThan(msg + " returned 0 result", answers.get().size(), 0);
            } catch (InterruptedException e) {
            }
        }
    }

    static private void assertGreaterThan(String msg, int a, int b) {
        assertTrue(msg + ": " + a + " > " + b, a > b);
    }

    static private void assertValidAnswer(String msg, @NonNull DnsAnswer ans) {
        // Check rcode field.(0, No error condition).
        assertTrue(msg + " Response error, rcode: " + ans.getRcode(), ans.getRcode() == 0);
        // Check answer counts.
        assertTrue(msg + " No answer found", ans.getANCount() > 0);
        // Check question counts.
        assertTrue(msg + " No question found", ans.getQDCount() > 0);
    }

    static private void assertValidEmptyAnswer(String msg, @NonNull DnsAnswer ans) {
        // Check rcode field.(0, No error condition).
        assertTrue(msg + " Response error, rcode: " + ans.getRcode(), ans.getRcode() == 0);
        // Check answer counts. Expect 0 answer.
        assertTrue(msg + " Not an empty answer", ans.getANCount() == 0);
        // Check question counts.
        assertTrue(msg + " No question found", ans.getQDCount() > 0);
    }

    private class DnsAnswer extends DnsPacket {
        DnsAnswer(@NonNull byte[] data) throws ParseException {
            super(data);
            // Check QR field.(query (0), or a response (1)).
            if ((mHeader.flags & (1 << 15)) == 0) {
                throw new ParseException("Not an answer packet");
            }
        }

        int getRcode() {
            return mHeader.rcode;
        }
        int getANCount(){
            return mHeader.getRecordCount(ANSECTION);
        }
        int getQDCount(){
            return mHeader.getRecordCount(QDSECTION);
        }
    }

    public void testRawQuery() throws ErrnoException {
        final String dname = "www.google.com";
        final String msg = "Raw query " + dname;
        for (Network network : getTestableNetworks()) {
            final CountDownLatch latch = new CountDownLatch(1);
            mDns.query(network, dname, CLASS_IN, TYPE_AAAA, FLAG_NO_CACHE_LOOKUP, mHandler,
                    answer -> {
                        if (answer == null) {
                            fail(msg + " no answer returned");
                        }
                        try {
                            assertValidAnswer(msg, new DnsAnswer(answer));
                            Log.d(TAG, "Reported blob:" + byteArrayToHexString(answer));
                            latch.countDown();
                        } catch (DnsPacket.ParseException e) {
                            fail(msg + e.getMessage());
                        }
                    }
            );
            try {
                assertTrue(msg + " but no answer after " + TIMEOUT_MS + "ms.",
                        latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            } catch (InterruptedException e) {
            }
        }
    }

    public void testRawQueryWithBlob() throws ErrnoException {
        final byte[] blob = new byte[]{
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
        final String msg = "Raw query with blob " + byteArrayToHexString(blob);
        for (Network network : getTestableNetworks()) {
            final CountDownLatch latch = new CountDownLatch(1);
            mDns.query(network, blob, FLAG_NO_CACHE_LOOKUP, mHandler, answer -> {
                        if (answer == null) {
                            fail(msg + " no answer returned");
                        }
                        try {
                            assertValidAnswer(msg, new DnsAnswer(answer));
                            Log.d(TAG, "Reported blob:" + byteArrayToHexString(answer));
                            latch.countDown();
                        } catch (DnsPacket.ParseException e) {
                            fail(msg + e.getMessage());
                        }
                    }
            );
            try {
                assertTrue(msg + " but no answer after " + TIMEOUT_MS + "ms.",
                        latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            } catch (InterruptedException e) {
            }
        }
    }

    public void testEmptyQuery() throws ErrnoException {
        final String dname = "";
        final String msg = "Raw query empty dname(ROOT)";
        for (Network network : getTestableNetworks()) {
            final CountDownLatch latch = new CountDownLatch(1);
            mDns.query(network, dname, CLASS_IN, TYPE_AAAA, FLAG_NO_CACHE_LOOKUP, mHandler,
                    answer -> {
                        if (answer == null) {
                            fail(msg + " no answer returned");
                        }
                        try {
                            // Except no answer record because of querying with empty dname(ROOT)
                            assertValidEmptyAnswer(msg, new DnsAnswer(answer));
                            latch.countDown();
                        } catch (DnsPacket.ParseException e) {
                            fail(msg + e.getMessage());
                        }
                    }
            );
            try {
                assertTrue(msg + " but no answer after " + TIMEOUT_MS + "ms.",
                        latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            } catch (InterruptedException e) {
            }
        }
    }

    public void testNXQuery() throws ErrnoException {
        final String dname = "test1-nx.metric.gstatic.com";
        final String msg = "InetAddress query " + dname;
        for (Network network : getTestableNetworks()) {
            final CountDownLatch latch = new CountDownLatch(1);
            mDns.query(network, dname, FLAG_NO_CACHE_LOOKUP, mHandler, answerList -> {
                        if (answerList.size() == 0) {
                            latch.countDown();
                            return;
                        }
                        fail(msg + " but get valid answers");
                    }
            );
            try {
                assertTrue(msg + " but no answer after " + TIMEOUT_MS + "ms.",
                        latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            } catch (InterruptedException e) {
            }
        }
    }
}
