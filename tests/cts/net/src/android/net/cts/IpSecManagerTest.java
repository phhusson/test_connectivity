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

import static android.system.OsConstants.IPPROTO_TCP;
import static android.system.OsConstants.IPPROTO_UDP;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecTransform;
import android.net.TrafficStats;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.test.AndroidTestCase;

import java.io.FileDescriptor;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
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

    private static final String IPV4_LOOPBACK = "127.0.0.1";
    private static final String IPV6_LOOPBACK = "::1";
    private static final int TCP_HDRLEN_WITH_OPTIONS = 32;
    private static final int UDP_HDRLEN = 8;
    private static final int IP4_HDRLEN = 20;
    private static final int IP6_HDRLEN = 40;

    private static final byte[] TEST_DATA = "Best test data ever!".getBytes();

    // Encryption parameters
    private static final int AES_CBC_IV_LEN = 16;
    private static final int AES_CBC_BLK_SIZE = 16;

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
            randomSpi = mISM.allocateSecurityParameterIndex(IpSecTransform.DIRECTION_OUT, addr);
            assertTrue(
                    "Failed to receive a valid SPI",
                    randomSpi.getSpi() != IpSecManager.INVALID_SECURITY_PARAMETER_INDEX);

            droidSpi =
                    mISM.allocateSecurityParameterIndex(
                            IpSecTransform.DIRECTION_IN, addr, DROID_SPI);
            assertTrue(
                    "Failed to allocate specified SPI, " + DROID_SPI,
                    droidSpi.getSpi() == DROID_SPI);

            try {
                mISM.allocateSecurityParameterIndex(IpSecTransform.DIRECTION_IN, addr, DROID_SPI);
                fail("Duplicate SPI was allowed to be created");
            } catch (IpSecManager.SpiUnavailableException expected) {
                // This is a success case because we expect a dupe SPI to throw
            }

            randomSpi.close();
            droidSpi.close();
        }
    }

    private byte[] getAuthKey(int bitLength) {
        return Arrays.copyOf(AUTH_KEY, bitLength / 8);
    }

    private static int getDomain(InetAddress address) {
        int domain;
        if (address instanceof Inet6Address)
            domain = OsConstants.AF_INET6;
        else
            domain = OsConstants.AF_INET;
        return domain;
    }

    /** This function finds an available port */
    private static int findUnusedPort() throws Exception {
        // Get an available port.
        DatagramSocket s = new DatagramSocket();
        int port = s.getLocalPort();
        s.close();
        return port;
    }

    private static FileDescriptor getBoundUdpSocket(InetAddress address) throws Exception {
        FileDescriptor sock =
                Os.socket(getDomain(address), OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP);

        for (int i = 0; i < MAX_PORT_BIND_ATTEMPTS; i++) {
            try {
                int port = findUnusedPort();
                Os.bind(sock, address, port);
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

    private void checkUnconnectedUdp(IpSecTransform transform, InetAddress local, int sendCount)
            throws Exception {
        FileDescriptor udpSocket = getBoundUdpSocket(local);
        int localPort = getPort(udpSocket);

        mISM.applyTransportModeTransform(udpSocket, transform);

        for (int i = 0; i < sendCount; i++) {
            byte[] in = new byte[TEST_DATA.length];
            Os.sendto(udpSocket, TEST_DATA, 0, TEST_DATA.length, 0, local, localPort);
            Os.read(udpSocket, in, 0, in.length);
            assertArrayEquals("Encapsulated data did not match.", TEST_DATA, in);
        }

        mISM.removeTransportModeTransform(udpSocket, transform);
        Os.close(udpSocket);
    }

    private void checkTcp(IpSecTransform transform, InetAddress local, int sendCount)
            throws Exception {
        FileDescriptor server =
            Os.socket(getDomain(local), OsConstants.SOCK_STREAM, IPPROTO_TCP);

        FileDescriptor client =
            Os.socket(getDomain(local), OsConstants.SOCK_STREAM, IPPROTO_TCP);

        Os.bind(server, local, 0);
        int port = ((InetSocketAddress) Os.getsockname(server)).getPort();

        mISM.applyTransportModeTransform(client, transform);
        mISM.applyTransportModeTransform(server, transform);

        Os.listen(server, 10);
        Os.connect(client, local, port);
        FileDescriptor accepted = Os.accept(server, null);

        mISM.applyTransportModeTransform(accepted, transform);

        // Wait for TCP handshake packets to be counted
        Thread.sleep(250);

        // Reset StatsChecker, to ignore negotiation overhead.
        StatsChecker.initStatsChecker();
        for (int i = 0; i < sendCount; i++) {
            byte[] in = new byte[TEST_DATA.length];

            Os.write(client, TEST_DATA, 0, TEST_DATA.length);
            Os.read(accepted, in, 0, in.length);
            assertArrayEquals("Client-to-server encrypted data did not match.", TEST_DATA, in);

            in = new byte[TEST_DATA.length];

            Os.write(accepted, TEST_DATA, 0, TEST_DATA.length);
            Os.read(client, in, 0, in.length);
            assertArrayEquals("Server-to-client encrypted data did not match.", TEST_DATA, in);
        }

        mISM.removeTransportModeTransform(server, transform);
        mISM.removeTransportModeTransform(client, transform);
        mISM.removeTransportModeTransform(accepted, transform);

        Os.close(server);
        Os.close(client);
        Os.close(accepted);
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
                mISM.allocateSecurityParameterIndex(IpSecTransform.DIRECTION_OUT, local);

        IpSecManager.SecurityParameterIndex inSpi =
                mISM.allocateSecurityParameterIndex(
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

    /** Snapshot of TrafficStats as of initStatsChecker call for later comparisons */
    private static class StatsChecker {
        private static final String LOOPBACK_INTERFACE = "lo";
        private static final double ERROR_MARGIN_BYTES = 1.05;
        private static final double ERROR_MARGIN_PKTS = 1.05;

        private static long uidTxBytes;
        private static long uidRxBytes;
        private static long uidTxPackets;
        private static long uidRxPackets;

        private static long ifaceTxBytes;
        private static long ifaceRxBytes;
        private static long ifaceTxPackets;
        private static long ifaceRxPackets;

        private static void assertUidStatsDelta(
                int expectedTxByteDelta,
                int expectedTxPacketDelta,
                int expectedRxByteDelta,
                int expectedRxPacketDelta) {
            long newUidTxBytes = TrafficStats.getUidTxBytes(Os.getuid());
            long newUidRxBytes = TrafficStats.getUidRxBytes(Os.getuid());
            long newUidTxPackets = TrafficStats.getUidTxPackets(Os.getuid());
            long newUidRxPackets = TrafficStats.getUidRxPackets(Os.getuid());

            assertEquals(expectedTxByteDelta, newUidTxBytes - uidTxBytes);
            assertEquals(expectedRxByteDelta, newUidRxBytes - uidRxBytes);
            assertEquals(expectedTxPacketDelta, newUidTxPackets - uidTxPackets);
            assertEquals(expectedRxPacketDelta, newUidRxPackets - uidRxPackets);
        }

        private static void assertIfaceStatsDelta(
                int expectedTxByteDelta,
                int expectedTxPacketDelta,
                int expectedRxByteDelta,
                int expectedRxPacketDelta)
                throws IOException {
            long newIfaceTxBytes = TrafficStats.getLoopbackTxBytes();
            long newIfaceRxBytes = TrafficStats.getLoopbackRxBytes();
            long newIfaceTxPackets = TrafficStats.getLoopbackTxPackets();
            long newIfaceRxPackets = TrafficStats.getLoopbackRxPackets();

            // Check that iface stats are within an acceptable range; data might be sent
            // on the local interface by other apps.
            assertApproxEquals(
                    ifaceTxBytes, newIfaceTxBytes, expectedTxByteDelta, ERROR_MARGIN_BYTES);
            assertApproxEquals(
                    ifaceRxBytes, newIfaceRxBytes, expectedRxByteDelta, ERROR_MARGIN_BYTES);
            assertApproxEquals(
                    ifaceTxPackets, newIfaceTxPackets, expectedTxPacketDelta, ERROR_MARGIN_PKTS);
            assertApproxEquals(
                    ifaceRxPackets, newIfaceRxPackets, expectedRxPacketDelta, ERROR_MARGIN_PKTS);
        }

        private static void assertApproxEquals(
                long oldStats, long newStats, int expectedDelta, double errorMargin) {
            assertTrue(expectedDelta <= newStats - oldStats);
            assertTrue((expectedDelta * errorMargin) > newStats - oldStats);
        }

        private static void initStatsChecker() throws IOException {
            uidTxBytes = TrafficStats.getUidTxBytes(Os.getuid());
            uidRxBytes = TrafficStats.getUidRxBytes(Os.getuid());
            uidTxPackets = TrafficStats.getUidTxPackets(Os.getuid());
            uidRxPackets = TrafficStats.getUidRxPackets(Os.getuid());

            ifaceTxBytes = TrafficStats.getLoopbackTxBytes();
            ifaceRxBytes = TrafficStats.getLoopbackRxBytes();
            ifaceTxPackets = TrafficStats.getLoopbackTxPackets();
            ifaceRxPackets = TrafficStats.getLoopbackRxPackets();
        }
    }

    /** Helper function to calculate expected ESP packet size. */
    private int calculateEspPacketSize(
            int payloadLen, int cryptIvLength, int cryptBlockSize, int authTruncLen) {
        final int ESP_HDRLEN = 4 + 4; // SPI + Seq#
        final int ICV_LEN = authTruncLen / 8; // Auth trailer; based on truncation length
        payloadLen += cryptIvLength; // Initialization Vector
        payloadLen += 2; // ESP trailer

        // Align to block size of encryption algorithm
        payloadLen += (cryptBlockSize - (payloadLen % cryptBlockSize)) % cryptBlockSize;
        return payloadLen + ESP_HDRLEN + ICV_LEN;
    }

    /** Helper function to calculate expected ESP packet size using AES-CBC encryption. */
    private int calculateAesCbcEspPacketSizeWithAuth(int payloadLen, int authTruncLen) {
        return calculateEspPacketSize(payloadLen, AES_CBC_IV_LEN, AES_CBC_BLK_SIZE, authTruncLen);
    }

    public void checkTransform(
            int protocol,
            String localAddress,
            IpSecAlgorithm crypt,
            IpSecAlgorithm auth,
            boolean doUdpEncap,
            int sendCount)
            throws Exception {
        StatsChecker.initStatsChecker();
        InetAddress local = InetAddress.getByName(localAddress);

        try (IpSecManager.UdpEncapsulationSocket encapSocket = mISM.openUdpEncapsulationSocket();
                IpSecManager.SecurityParameterIndex outSpi =
                        mISM.allocateSecurityParameterIndex(IpSecTransform.DIRECTION_OUT, local);
                IpSecManager.SecurityParameterIndex inSpi =
                        mISM.allocateSecurityParameterIndex(
                                IpSecTransform.DIRECTION_IN, local, outSpi.getSpi())) {

            IpSecTransform.Builder transformBuilder =
                    new IpSecTransform.Builder(mContext)
                            .setSpi(IpSecTransform.DIRECTION_OUT, outSpi)
                            .setEncryption(IpSecTransform.DIRECTION_OUT, crypt)
                            .setAuthentication(IpSecTransform.DIRECTION_OUT, auth)
                            .setSpi(IpSecTransform.DIRECTION_IN, inSpi)
                            .setEncryption(IpSecTransform.DIRECTION_IN, crypt)
                            .setAuthentication(IpSecTransform.DIRECTION_IN, auth);

            if (doUdpEncap) {
                transformBuilder =
                        transformBuilder.setIpv4Encapsulation(encapSocket, encapSocket.getPort());
            }

            int ipHdrLen = local instanceof Inet6Address ? IP6_HDRLEN : IP4_HDRLEN;
            int transportHdrLen = 0;
            int udpEncapLen = doUdpEncap ? UDP_HDRLEN : 0;

            try (IpSecTransform transform = transformBuilder.buildTransportModeTransform(local)) {
                if (protocol == IPPROTO_TCP) {
                    transportHdrLen = TCP_HDRLEN_WITH_OPTIONS;
                    checkTcp(transform, local, sendCount);
                } else if (protocol == IPPROTO_UDP) {
                    transportHdrLen = UDP_HDRLEN;

                    // TODO: Also check connected udp.
                    checkUnconnectedUdp(transform, local, sendCount);
                } else {
                    throw new IllegalArgumentException("Invalid protocol");
                }
            }

            // Wait for stats to be counted
            Thread.sleep(250);

            checkStatsChecker(
                    protocol,
                    ipHdrLen,
                    transportHdrLen,
                    udpEncapLen,
                    sendCount,
                    auth.getTruncationLengthBits());
        }
    }

    private void checkStatsChecker(
            int protocol,
            int ipHdrLen,
            int transportHdrLen,
            int udpEncapLen,
            int sendCount,
            int truncLenBits)
            throws Exception {

        int innerPacketSize = TEST_DATA.length + transportHdrLen + ipHdrLen;
        int outerPacketSize =
                calculateAesCbcEspPacketSizeWithAuth(
                                TEST_DATA.length + transportHdrLen, truncLenBits)
                        + udpEncapLen
                        + ipHdrLen;

        int expectedOuterBytes = outerPacketSize * sendCount;
        int expectedInnerBytes = innerPacketSize * sendCount;
        int expectedPackets = sendCount;

        // Add TCP ACKs for data packets
        if (protocol == IPPROTO_TCP) {
            int encryptedTcpPktSize =
                    calculateAesCbcEspPacketSizeWithAuth(TCP_HDRLEN_WITH_OPTIONS, truncLenBits);

                // Each run sends two packets, one in each direction.
                sendCount *= 2;
                expectedOuterBytes *= 2;
                expectedInnerBytes *= 2;
                expectedPackets *= 2;

                // Add data packet ACKs
                expectedOuterBytes += (encryptedTcpPktSize + udpEncapLen + ipHdrLen) * (sendCount);
                expectedInnerBytes += (TCP_HDRLEN_WITH_OPTIONS + ipHdrLen) * (sendCount);
                expectedPackets += sendCount;
        }

        if (udpEncapLen != 0) {
            StatsChecker.assertUidStatsDelta(
                    expectedOuterBytes, expectedPackets, expectedOuterBytes, expectedPackets);
        } else {
            StatsChecker.assertUidStatsDelta(
                    expectedOuterBytes, expectedPackets, expectedInnerBytes, expectedPackets);
        }

        // Unreliable at low numbers due to potential interference from other processes.
        if (sendCount >= 1000) {
            StatsChecker.assertIfaceStatsDelta(
                    expectedOuterBytes, expectedPackets, expectedOuterBytes, expectedPackets);
        }
    }

    public void testIkeOverUdpEncapSocket() throws Exception {
        // IPv6 not supported for UDP-encap-ESP
        InetAddress local = InetAddress.getByName(IPV4_LOOPBACK);
        StatsChecker.initStatsChecker();

        try (IpSecManager.UdpEncapsulationSocket encapSocket = mISM.openUdpEncapsulationSocket()) {
            int localPort = getPort(encapSocket.getSocket());

            // Append ESP header - 4 bytes of SPI, 4 bytes of seq number
            byte[] dataWithEspHeader = new byte[TEST_DATA.length + 8];
            System.arraycopy(TEST_DATA, 0, dataWithEspHeader, 8, TEST_DATA.length);

            byte[] in = new byte[dataWithEspHeader.length];
            Os.sendto(
                    encapSocket.getSocket(),
                    dataWithEspHeader,
                    0,
                    dataWithEspHeader.length,
                    0,
                    local,
                    localPort);
            Os.read(encapSocket.getSocket(), in, 0, in.length);
            assertArrayEquals("Encapsulated data did not match.", dataWithEspHeader, in);

            int ipHdrLen = local instanceof Inet6Address ? IP6_HDRLEN : IP4_HDRLEN;
            int expectedPacketSize = dataWithEspHeader.length + UDP_HDRLEN + ipHdrLen;
            StatsChecker.assertUidStatsDelta(expectedPacketSize, 1, expectedPacketSize, 1);
            StatsChecker.assertIfaceStatsDelta(expectedPacketSize, 1, expectedPacketSize, 1);
        }
    }

    // TODO: Check IKE over ESP sockets (IPv4, IPv6) - does this need SOCK_RAW?

    /* TODO: Re-enable these when policy matcher works for reflected packets
     *
     * The issue here is that A sends to B, and everything is new; therefore PREROUTING counts
     * correctly. But it appears that the security path is not cleared afterwards, thus when A
     * sends an ACK back to B, the policy matcher flags it as a "IPSec" packet. See b/70635417
     */

    // public void testInterfaceCountersTcp4() throws Exception {
    //     IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
    //     IpSecAlgorithm auth = new IpSecAlgorithm(
    //             IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
    //     checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, false, 1000);
    // }

    // public void testInterfaceCountersTcp6() throws Exception {
    //     IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
    //     IpSecAlgorithm auth = new IpSecAlgorithm(
    //             IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
    //     checkTransform(IPPROTO_TCP, IPV6_LOOPBACK, crypt, auth, false, 1000);
    // }

    // public void testInterfaceCountersTcp4UdpEncap() throws Exception {
    //     IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
    //     IpSecAlgorithm auth =
    //             new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
    //     checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, true, 1000);
    // }

    public void testInterfaceCountersUdp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, false, 1000);
    }

    public void testInterfaceCountersUdp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
        checkTransform(IPPROTO_UDP, IPV6_LOOPBACK, crypt, auth, false, 1000);
    }

    public void testInterfaceCountersUdp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, true, 1000);
    }

    public void testAesCbcHmacMd5Tcp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacMd5Tcp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
        checkTransform(IPPROTO_TCP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacMd5Udp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacMd5Udp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
        checkTransform(IPPROTO_UDP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha1Tcp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA1, getAuthKey(160), 96);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha1Tcp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA1, getAuthKey(160), 96);
        checkTransform(IPPROTO_TCP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha1Udp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA1, getAuthKey(160), 96);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha1Udp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA1, getAuthKey(160), 96);
        checkTransform(IPPROTO_UDP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha256Tcp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA256, getAuthKey(256), 128);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha256Tcp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA256, getAuthKey(256), 128);
        checkTransform(IPPROTO_TCP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha256Udp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA256, getAuthKey(256), 128);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha256Udp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA256, getAuthKey(256), 128);
        checkTransform(IPPROTO_UDP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha384Tcp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA384, getAuthKey(384), 192);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha384Tcp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA384, getAuthKey(384), 192);
        checkTransform(IPPROTO_TCP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha384Udp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA384, getAuthKey(384), 192);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha384Udp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA384, getAuthKey(384), 192);
        checkTransform(IPPROTO_UDP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha512Tcp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA512, getAuthKey(512), 256);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha512Tcp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA512, getAuthKey(512), 256);
        checkTransform(IPPROTO_TCP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha512Udp4() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA512, getAuthKey(512), 256);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacSha512Udp6() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(
                IpSecAlgorithm.AUTH_HMAC_SHA512, getAuthKey(512), 256);
        checkTransform(IPPROTO_UDP, IPV6_LOOPBACK, crypt, auth, false, 1);
    }

    public void testAesCbcHmacMd5Tcp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, true, 1);
    }

    public void testAesCbcHmacMd5Udp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth = new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_MD5, getAuthKey(128), 96);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, true, 1);
    }

    public void testAesCbcHmacSha1Tcp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth =
                new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA1, getAuthKey(160), 96);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, true, 1);
    }

    public void testAesCbcHmacSha1Udp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth =
                new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA1, getAuthKey(160), 96);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, true, 1);
    }

    public void testAesCbcHmacSha256Tcp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth =
                new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA256, getAuthKey(256), 128);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, true, 1);
    }

    public void testAesCbcHmacSha256Udp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth =
                new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA256, getAuthKey(256), 128);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, true, 1);
    }

    public void testAesCbcHmacSha384Tcp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth =
                new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA384, getAuthKey(384), 192);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, true, 1);
    }

    public void testAesCbcHmacSha384Udp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth =
                new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA384, getAuthKey(384), 192);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, true, 1);
    }

    public void testAesCbcHmacSha512Tcp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth =
                new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA512, getAuthKey(512), 256);
        checkTransform(IPPROTO_TCP, IPV4_LOOPBACK, crypt, auth, true, 1);
    }

    public void testAesCbcHmacSha512Udp4UdpEncap() throws Exception {
        IpSecAlgorithm crypt = new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, CRYPT_KEY);
        IpSecAlgorithm auth =
                new IpSecAlgorithm(IpSecAlgorithm.AUTH_HMAC_SHA512, getAuthKey(512), 256);
        checkTransform(IPPROTO_UDP, IPV4_LOOPBACK, crypt, auth, true, 1);
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
                        mISM.allocateSecurityParameterIndex(IpSecTransform.DIRECTION_OUT, local);
                IpSecManager.SecurityParameterIndex inSpi =
                        mISM.allocateSecurityParameterIndex(
                                IpSecTransform.DIRECTION_IN, local, outSpi.getSpi());
                IpSecTransform transform =
                        buildIpSecTransform(mContext, inSpi, outSpi, encapSocket, local)) {

            // Create user socket, apply transform to it
            FileDescriptor udpSocket = null;
            try {
                udpSocket = getBoundUdpSocket(local);
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
                        mISM.allocateSecurityParameterIndex(IpSecTransform.DIRECTION_OUT, local);
                IpSecManager.SecurityParameterIndex inSpi =
                        mISM.allocateSecurityParameterIndex(IpSecTransform.DIRECTION_IN, local);
                IpSecTransform transform =
                        buildIpSecTransform(mContext, inSpi, outSpi, encapSocket, local)) {

            // Create user socket, apply transform to it
            FileDescriptor sock = null;

            try {
                sock = getBoundUdpSocket(local);
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
}
