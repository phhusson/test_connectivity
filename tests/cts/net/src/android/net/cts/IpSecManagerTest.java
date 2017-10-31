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
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.test.AndroidTestCase;
import java.io.FileDescriptor;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.UnknownHostException;
import java.util.Arrays;

public class IpSecManagerTest extends AndroidTestCase {

    private static final String TAG = IpSecManagerTest.class.getSimpleName();

    private IpSecManager mISM;

    private ConnectivityManager mCM;

    private static InetAddress IpAddress(String addrString) {
        try {
            return InetAddress.getByName(addrString);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IP address: " + e);
        }
    }

    private static final InetAddress GOOGLE_DNS_4 = IpAddress("8.8.8.8");
    private static final InetAddress GOOGLE_DNS_6 = IpAddress("2001:4860:4860::8888");
    private static final InetAddress LOOPBACK_4 = IpAddress("127.0.0.1");

    private static final InetAddress[] GOOGLE_DNS_LIST =
            new InetAddress[] {GOOGLE_DNS_4, GOOGLE_DNS_6};

    private static final int DROID_SPI = 0xD1201D;
    private static final int MAX_PORT_BIND_ATTEMPTS = 10;

    private static final byte[] CRYPT_KEY = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    private static final byte[] AUTH_KEY = {
        0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F,
        0x7A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F
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
            randomSpi = mISM.reserveSecurityParameterIndex(IpSecTransform.DIRECTION_OUT, addr);
            assertTrue(
                    "Failed to receive a valid SPI",
                    randomSpi.getSpi() != IpSecManager.INVALID_SECURITY_PARAMETER_INDEX);

            droidSpi =
                    mISM.reserveSecurityParameterIndex(
                            IpSecTransform.DIRECTION_IN, addr, DROID_SPI);
            assertTrue(
                    "Failed to allocate specified SPI, " + DROID_SPI,
                    droidSpi.getSpi() == DROID_SPI);

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
        InetAddress local = LOOPBACK_4;
        IpSecManager.SecurityParameterIndex outSpi =
                mISM.reserveSecurityParameterIndex(IpSecTransform.DIRECTION_OUT, local);

        IpSecManager.SecurityParameterIndex inSpi =
                mISM.reserveSecurityParameterIndex(
                        IpSecTransform.DIRECTION_IN, local, outSpi.getSpi());

        IpSecTransform transform =
                new IpSecTransform.Builder(mContext)
                        .setSpi(IpSecTransform.DIRECTION_OUT, outSpi)
                        .setEncryption(
                                IpSecTransform.DIRECTION_OUT,
                                new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY))
                        .setAuthentication(
                                IpSecTransform.DIRECTION_OUT,
                                new IpSecAlgorithm(
                                        IpSecAlgorithm.AUTH_HMAC_SHA256,
                                        AUTH_KEY,
                                        AUTH_KEY.length * 8))
                        .setSpi(IpSecTransform.DIRECTION_IN, inSpi)
                        .setEncryption(
                                IpSecTransform.DIRECTION_IN,
                                new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY))
                        .setAuthentication(
                                IpSecTransform.DIRECTION_IN,
                                new IpSecAlgorithm(
                                        IpSecAlgorithm.AUTH_HMAC_SHA256,
                                        AUTH_KEY,
                                        CRYPT_KEY.length * 8))
                        .buildTransportModeTransform(local);

        // Bind localSocket to a random available port.
        DatagramSocket localSocket = new DatagramSocket(0);
        int localPort = localSocket.getLocalPort();
        localSocket.setSoTimeout(500);
        ParcelFileDescriptor pin = ParcelFileDescriptor.fromDatagramSocket(localSocket);
        FileDescriptor udpSocket = pin.getFileDescriptor();

        mISM.applyTransportModeTransform(udpSocket, transform);
        byte[] data = new String("Best test data ever!").getBytes("UTF-8");

        byte[] in = new byte[data.length];
        Os.sendto(udpSocket, data, 0, data.length, 0, local, localPort);
        Os.read(udpSocket, in, 0, in.length);
        assertTrue("Encapsulated data did not match.", Arrays.equals(data, in));
        mISM.removeTransportModeTransform(udpSocket, transform);
        Os.close(udpSocket);
        transform.close();
    }

    public void testOpenUdpEncapSocketSpecificPort() throws Exception {
        IpSecManager.UdpEncapsulationSocket encapSocket = null;
        int port = -1;
        for (int i = 0; i < MAX_PORT_BIND_ATTEMPTS; i++) {
            try {
                port = findUnusedPort();
                encapSocket = mISM.openUdpEncapsulationSocket(port);
                break;
            } catch (ErrnoException e) {
                if (e.errno == OsConstants.EADDRINUSE) {
                    // Someone claimed the port since we called findUnusedPort.
                    continue;
                }
                throw e;
            } finally {
                if (encapSocket != null) {
                    encapSocket.close();
                }
            }
        }

        if (encapSocket == null) {
            fail("Failed " + MAX_PORT_BIND_ATTEMPTS + " attempts to bind to a port");
        }

        assertTrue("Returned invalid port", encapSocket.getPort() == port);
    }

    public void testOpenUdpEncapSocketRandomPort() throws Exception {
        try (IpSecManager.UdpEncapsulationSocket encapSocket = mISM.openUdpEncapsulationSocket()) {
            assertTrue("Returned invalid port", encapSocket.getPort() != 0);
        }
    }

    public void testUdpEncapsulation() throws Exception {
        InetAddress local = LOOPBACK_4;

        // TODO: Refactor to make this more representative of a normal application use case. (use
        // separate sockets for inbound and outbound)
        // Create SPIs, UDP encap socket
        try (IpSecManager.UdpEncapsulationSocket encapSocket = mISM.openUdpEncapsulationSocket();
                IpSecManager.SecurityParameterIndex outSpi =
                        mISM.reserveSecurityParameterIndex(IpSecTransform.DIRECTION_OUT, local);
                IpSecManager.SecurityParameterIndex inSpi =
                        mISM.reserveSecurityParameterIndex(
                                IpSecTransform.DIRECTION_IN, local, outSpi.getSpi());
                IpSecTransform transform =
                        buildIpSecTransform(mContext, inSpi, outSpi, encapSocket, local)) {

            // Create user socket, apply transform to it
            FileDescriptor udpSocket = null;
            try {
                udpSocket = getTestV4UdpSocket(local);
                int port = getPort(udpSocket);

                mISM.applyTransportModeTransform(udpSocket, transform);

                // Send an ESP packet from this socket to itself. Since the inbound and
                // outbound transforms match, we should receive the data we sent.
                byte[] data = new String("IPSec UDP-encap-ESP test data").getBytes("UTF-8");
                Os.sendto(udpSocket, data, 0, data.length, 0, local, port);
                byte[] in = new byte[data.length];
                Os.read(udpSocket, in, 0, in.length);
                assertTrue("Encapsulated data did not match.", Arrays.equals(data, in));

                // Send an IKE packet from this socket to itself. IKE packets (SPI of 0)
                // are not transformed in any way, and should be sent in the clear
                // We expect this to work too (no inbound transforms)
                final byte[] header = new byte[] {0, 0, 0, 0};
                final String message = "Sample IKE Packet";
                data = (new String(header) + message).getBytes("UTF-8");
                Os.sendto(
                        encapSocket.getSocket(),
                        data,
                        0,
                        data.length,
                        0,
                        local,
                        encapSocket.getPort());
                in = new byte[data.length];
                Os.read(encapSocket.getSocket(), in, 0, in.length);
                assertTrue(
                        "Encap socket was unable to send/receive IKE data",
                        Arrays.equals(data, in));

                mISM.removeTransportModeTransform(udpSocket, transform);
            } finally {
                if (udpSocket != null) {
                    Os.close(udpSocket);
                }
            }
        }
    }

    public void testIke() throws Exception {
        InetAddress local = LOOPBACK_4;

        // TODO: Refactor to make this more representative of a normal application use case. (use
        // separate sockets for inbound and outbound)
        try (IpSecManager.UdpEncapsulationSocket encapSocket = mISM.openUdpEncapsulationSocket();
                IpSecManager.SecurityParameterIndex outSpi =
                        mISM.reserveSecurityParameterIndex(IpSecTransform.DIRECTION_OUT, local);
                IpSecManager.SecurityParameterIndex inSpi =
                        mISM.reserveSecurityParameterIndex(IpSecTransform.DIRECTION_IN, local);
                IpSecTransform transform =
                        buildIpSecTransform(mContext, inSpi, outSpi, encapSocket, local)) {

            // Create user socket, apply transform to it
            FileDescriptor sock = null;

            try {
                sock = getTestV4UdpSocket(local);
                int port = getPort(sock);

                mISM.applyTransportModeTransform(sock, transform);

                // TODO: Find a way to set a timeout on the socket, and assert the ESP packet
                // doesn't make it through. Setting sockopts currently throws EPERM (possibly
                // because it is owned by a different UID).

                // Send ESP packet from our socket to the encap socket. The SPIs do not
                // match, and we should expect this packet to be dropped.
                byte[] header = new byte[] {1, 1, 1, 1};
                String message = "Sample ESP Packet";
                byte[] data = (new String(header) + message).getBytes("UTF-8");
                Os.sendto(sock, data, 0, data.length, 0, local, encapSocket.getPort());

                // Send IKE packet from the encap socket to itself. Since IKE is not
                // transformed in any way, this should succeed.
                header = new byte[] {0, 0, 0, 0};
                message = "Sample IKE Packet";
                data = (new String(header) + message).getBytes("UTF-8");
                Os.sendto(
                        encapSocket.getSocket(),
                        data,
                        0,
                        data.length,
                        0,
                        local,
                        encapSocket.getPort());

                // ESP data should be dropped, due to different input SPI (as opposed to being
                // readable from the encapSocket)
                // Thus, only IKE data should be received from the socket.
                // If the first four bytes are zero, assume non-ESP (IKE) traffic.
                // Expect an nulled out SPI just as we sent out, without being modified.
                byte[] in = new byte[4];
                in[0] = 1; // Make sure the array has to be overwritten to pass
                Os.read(encapSocket.getSocket(), in, 0, in.length);
                assertTrue(
                        "Encap socket received UDP-encap-ESP data despite invalid SPIs",
                        Arrays.equals(header, in));

                mISM.removeTransportModeTransform(sock, transform);
            } finally {
                if (sock != null) {
                    Os.close(sock);
                }
            }
        }
    }

    /** This function finds an available port */
    private static int findUnusedPort() throws Exception {
        // Get an available port.
        ServerSocket s = new ServerSocket(0);
        int port = s.getLocalPort();
        s.close();
        return port;
    }

    private static IpSecTransform buildIpSecTransform(
            Context mContext,
            IpSecManager.SecurityParameterIndex inSpi,
            IpSecManager.SecurityParameterIndex outSpi,
            IpSecManager.UdpEncapsulationSocket encapSocket,
            InetAddress remoteAddr)
            throws Exception {
        return new IpSecTransform.Builder(mContext)
                .setSpi(IpSecTransform.DIRECTION_IN, inSpi)
                .setSpi(IpSecTransform.DIRECTION_OUT, outSpi)
                .setEncryption(
                        IpSecTransform.DIRECTION_IN,
                        new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY))
                .setEncryption(
                        IpSecTransform.DIRECTION_OUT,
                        new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY))
                .setAuthentication(
                        IpSecTransform.DIRECTION_IN,
                        new IpSecAlgorithm(
                                IpSecAlgorithm.AUTH_HMAC_SHA256, AUTH_KEY, AUTH_KEY.length * 4))
                .setAuthentication(
                        IpSecTransform.DIRECTION_OUT,
                        new IpSecAlgorithm(
                                IpSecAlgorithm.AUTH_HMAC_SHA256, AUTH_KEY, AUTH_KEY.length * 4))
                .setIpv4Encapsulation(encapSocket, encapSocket.getPort())
                .buildTransportModeTransform(remoteAddr);
    }

    private static int getPort(FileDescriptor sock) throws Exception {
        return ((InetSocketAddress) Os.getsockname(sock)).getPort();
    }

    private static FileDescriptor getTestV4UdpSocket(InetAddress v4Addr) throws Exception {
        FileDescriptor sock =
                Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP);

        for (int i = 0; i < MAX_PORT_BIND_ATTEMPTS; i++) {
            try {
                int port = findUnusedPort();
                Os.bind(sock, v4Addr, port);
                break;
            } catch (ErrnoException e) {
                // Someone claimed the port since we called findUnusedPort.
                if (e.errno == OsConstants.EADDRINUSE) {
                    if (i == MAX_PORT_BIND_ATTEMPTS - 1) {

                        fail("Failed " + MAX_PORT_BIND_ATTEMPTS + " attempts to bind to a port");
                    }
                    continue;
                }
                throw e.rethrowAsIOException();
            }
        }
        return sock;
    }
}
