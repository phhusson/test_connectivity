/*
 * Copyright (C) 2017 The Android Open Source Project
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

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecTransform;
import android.test.AndroidTestCase;
import android.util.Log;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

public class IpSecManagerTest extends AndroidTestCase {

    private static final String TAG = IpSecManagerTest.class.getSimpleName();

    private IpSecManager mISM;

    private ConnectivityManager mCM;

    private static final InetAddress GOOGLE_DNS_4;
    private static final InetAddress GOOGLE_DNS_6;

    static {
        try {
            // Google Public DNS Addresses;
            GOOGLE_DNS_4 = InetAddress.getByName("8.8.8.8");
            GOOGLE_DNS_6 = InetAddress.getByName("2001:4860:4860::8888");
        } catch (UnknownHostException e) {
            throw new RuntimeException("Could not resolve DNS Addresses", e);
        }
    }

    private static final InetAddress[] GOOGLE_DNS_LIST =
            new InetAddress[] {GOOGLE_DNS_4, GOOGLE_DNS_6};

    private static final int DROID_SPI = 0xD1201D;

    private static final byte[] CRYPT_KEY =
            new byte[] {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F
            };
    private static final byte[] AUTH_KEY =
            new byte[] {
                0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x7F
            };

    protected void setUp() throws Exception {
        super.setUp();
        mCM = (ConnectivityManager) getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        mISM = (IpSecManager) getContext().getSystemService(Context.IPSEC_SERVICE);
    }

    /*
     * Allocate a random SPI
     * Allocate a specific SPI using previous randomly created SPI value
     * Realloc the same SPI that was specifically created (expect SpiUnavailable)
     * Close SPIs
     */
    public void testAllocSpi() throws Exception {
        for (InetAddress addr : GOOGLE_DNS_LIST) {
            IpSecManager.SecurityParameterIndex randomSpi = null, droidSpi = null;
            randomSpi =
                    mISM.reserveSecurityParameterIndex(
                            IpSecTransform.DIRECTION_OUT,
                            addr,
                            IpSecManager.INVALID_SECURITY_PARAMETER_INDEX);
            assertTrue(randomSpi.getSpi() != IpSecManager.INVALID_SECURITY_PARAMETER_INDEX);

            droidSpi =
                    mISM.reserveSecurityParameterIndex(
                            IpSecTransform.DIRECTION_IN, addr, DROID_SPI);
            assertTrue(droidSpi.getSpi() == DROID_SPI);

            try {
                mISM.reserveSecurityParameterIndex(IpSecTransform.DIRECTION_IN, addr, DROID_SPI);
                fail("Duplicate SPI was allowed to be created");
            } catch (IpSecManager.SpiUnavailableException expected) {
                // This is a success case because we expect a dupe SPI to throw
            }

            randomSpi.close();
            droidSpi.close();
        }
    }

    /*
     * Alloc outbound SPI
     * Alloc inbound SPI
     * Create transport mode transform
     * open socket
     * apply transform to socket
     * send data on socket
     * release transform
     * send data (expect exception)
     */
    public void testCreateTransform() throws Exception {
        InetAddress local = InetAddress.getLoopbackAddress();
        IpSecManager.SecurityParameterIndex outSpi =
                mISM.reserveSecurityParameterIndex(
                        IpSecTransform.DIRECTION_OUT,
                        local,
                        IpSecManager.INVALID_SECURITY_PARAMETER_INDEX);

        IpSecManager.SecurityParameterIndex inSpi =
                mISM.reserveSecurityParameterIndex(
                        IpSecTransform.DIRECTION_IN, local, outSpi.getSpi());

        IpSecTransform transform =
                new IpSecTransform.Builder(mContext)
                        .setSpi(IpSecTransform.DIRECTION_OUT, outSpi)
                        .setEncryption(
                                IpSecTransform.DIRECTION_OUT,
                                new IpSecAlgorithm(IpSecAlgorithm.ALGO_CRYPT_AES_CBC, CRYPT_KEY))
                        .setAuthentication(
                                IpSecTransform.DIRECTION_OUT,
                                new IpSecAlgorithm(
                                        IpSecAlgorithm.ALGO_AUTH_HMAC_SHA256,
                                        AUTH_KEY,
                                        AUTH_KEY.length * 8))
                        .setSpi(IpSecTransform.DIRECTION_IN, inSpi)
                        .setEncryption(
                                IpSecTransform.DIRECTION_IN,
                                new IpSecAlgorithm(IpSecAlgorithm.ALGO_CRYPT_AES_CBC, CRYPT_KEY))
                        .setAuthentication(
                                IpSecTransform.DIRECTION_IN,
                                new IpSecAlgorithm(
                                        IpSecAlgorithm.ALGO_AUTH_HMAC_SHA256,
                                        AUTH_KEY,
                                        CRYPT_KEY.length * 8))
                        .buildTransportModeTransform(local);

        DatagramSocket localSocket;
        localSocket = new DatagramSocket(8888);

        localSocket.setSoTimeout(500);
        mISM.applyTransportModeTransform(localSocket, transform);
        byte[] data = new String("Best test data ever!").getBytes("UTF-8");

        DatagramPacket out = new DatagramPacket(data, data.length, local, 8888);
        localSocket.send(out);
        DatagramPacket in = new DatagramPacket(new byte[data.length], data.length);

        localSocket.receive(in);
        Log.d(TAG, Arrays.toString(data));
        Log.d(TAG, Arrays.toString(in.getData()));
        assertTrue(Arrays.equals(data, in.getData()));
        transform.close();
        try {
            localSocket.send(out);
        } catch (IOException e) {
        }

        mISM.removeTransportModeTransform(localSocket, transform);
    }
}
