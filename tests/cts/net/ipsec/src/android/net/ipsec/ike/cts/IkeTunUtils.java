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

import static android.net.ipsec.ike.cts.PacketUtils.BytePayload;
import static android.net.ipsec.ike.cts.PacketUtils.IP4_HDRLEN;
import static android.net.ipsec.ike.cts.PacketUtils.IP6_HDRLEN;
import static android.net.ipsec.ike.cts.PacketUtils.Ip4Header;
import static android.net.ipsec.ike.cts.PacketUtils.Ip6Header;
import static android.net.ipsec.ike.cts.PacketUtils.IpHeader;
import static android.net.ipsec.ike.cts.PacketUtils.Payload;
import static android.net.ipsec.ike.cts.PacketUtils.UDP_HDRLEN;
import static android.net.ipsec.ike.cts.PacketUtils.UdpHeader;
import static android.system.OsConstants.IPPROTO_UDP;

import static org.junit.Assert.fail;

import android.os.ParcelFileDescriptor;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class IkeTunUtils extends TunUtils {
    private static final int PORT_LEN = 2;

    private static final int NON_ESP_MARKER_LEN = 4;
    private static final byte[] NON_ESP_MARKER = new byte[NON_ESP_MARKER_LEN];

    private static final int IKE_HEADER_LEN = 28;
    private static final int IKE_INIT_SPI_OFFSET = 0;
    private static final int IKE_IS_RESP_BYTE_OFFSET = 19;
    private static final int IKE_MSG_ID_OFFSET = 20;

    public IkeTunUtils(ParcelFileDescriptor tunFd) {
        super(tunFd);
    }

    /**
     * Await the expected IKE request and inject an IKE response.
     *
     * @param respIkePkt IKE response packet without IP/UDP headers or NON ESP MARKER.
     */
    public byte[] awaitReqAndInjectResp(
            long expectedInitIkeSpi, int expectedMsgId, boolean expectedUseEncap, byte[] respIkePkt)
            throws Exception {
        byte[] request =
                awaitIkePacket(
                        expectedInitIkeSpi,
                        expectedMsgId,
                        false /* expectedResp */,
                        expectedUseEncap);

        // Build response header by flipping address and port
        InetAddress srcAddr = getAddress(request, false /* shouldGetSource */);
        InetAddress dstAddr = getAddress(request, true /* shouldGetSource */);
        int srcPort = getPort(request, false /* shouldGetSource */);
        int dstPort = getPort(request, true /* shouldGetSource */);

        byte[] response =
                buildIkePacket(srcAddr, dstAddr, srcPort, dstPort, expectedUseEncap, respIkePkt);
        injectPacket(response);
        return request;
    }

    private byte[] awaitIkePacket(
            long expectedInitIkeSpi,
            int expectedMsgId,
            boolean expectedResp,
            boolean expectedUseEncap)
            throws Exception {
        long endTime = System.currentTimeMillis() + TIMEOUT;
        int startIndex = 0;
        synchronized (mPackets) {
            while (System.currentTimeMillis() < endTime) {
                byte[] ikePkt =
                        getFirstMatchingPacket(
                                (pkt) -> {
                                    return isIke(
                                            pkt,
                                            expectedInitIkeSpi,
                                            expectedMsgId,
                                            expectedResp,
                                            expectedUseEncap);
                                },
                                startIndex);
                if (ikePkt != null) {
                    return ikePkt; // We've found the packet we're looking for.
                }

                startIndex = mPackets.size();

                // Try to prevent waiting too long. If waitTimeout <= 0, we've already hit timeout
                long waitTimeout = endTime - System.currentTimeMillis();
                if (waitTimeout > 0) {
                    mPackets.wait(waitTimeout);
                }
            }

            String direction = expectedResp ? "response" : "request";
            fail(
                    "No such IKE "
                            + direction
                            + " found with Initiator SPI "
                            + expectedInitIkeSpi
                            + " and message ID "
                            + expectedMsgId);
        }

        throw new IllegalStateException(
                "Hit an impossible case where fail() didn't throw an exception");
    }

    private static boolean isIke(
            byte[] pkt,
            long expectedInitIkeSpi,
            int expectedMsgId,
            boolean expectedResp,
            boolean expectedUseEncap) {
        int ipProtocolOffset = 0;
        int ikeOffset = 0;
        if (isIpv6(pkt)) {
            // IPv6 UDP expectedUseEncap not supported by kernels; assume non-expectedUseEncap.
            ipProtocolOffset = IP6_PROTO_OFFSET;
            ikeOffset = IP6_HDRLEN + UDP_HDRLEN;
        } else {
            // Use default IPv4 header length (assuming no options)
            ipProtocolOffset = IP4_PROTO_OFFSET;
            ikeOffset = IP4_HDRLEN + UDP_HDRLEN;

            if (expectedUseEncap) {
                if (hasNonEspMarker(pkt)) {
                    ikeOffset += NON_ESP_MARKER_LEN;
                } else {
                    return false;
                }
            }
        }

        return pkt[ipProtocolOffset] == IPPROTO_UDP
                && areSpiAndMsgIdEqual(
                        pkt, ikeOffset, expectedInitIkeSpi, expectedMsgId, expectedResp);
    }

    private static boolean hasNonEspMarker(byte[] pkt) {
        ByteBuffer buffer = ByteBuffer.wrap(pkt);
        int ikeOffset = IP4_HDRLEN + UDP_HDRLEN;
        if (buffer.remaining() < ikeOffset) return false;

        buffer.get(new byte[ikeOffset]); // Skip IP and UDP header
        byte[] nonEspMarker = new byte[NON_ESP_MARKER_LEN];
        if (buffer.remaining() < NON_ESP_MARKER_LEN) return false;

        buffer.get(nonEspMarker);
        return Arrays.equals(NON_ESP_MARKER, nonEspMarker);
    }

    private static boolean areSpiAndMsgIdEqual(
            byte[] pkt,
            int ikeOffset,
            long expectedIkeInitSpi,
            int expectedMsgId,
            boolean expectedResp) {
        if (pkt.length <= ikeOffset + IKE_HEADER_LEN) return false;

        ByteBuffer buffer = ByteBuffer.wrap(pkt);
        buffer.get(new byte[ikeOffset]); // Skip IP, UDP header (and NON_ESP_MARKER)

        // Check message ID.
        buffer.get(new byte[IKE_MSG_ID_OFFSET]);
        int msgId = buffer.getInt();
        return expectedMsgId == msgId;

        // TODO: Check SPI and packet direction
    }

    private static InetAddress getAddress(byte[] pkt, boolean shouldGetSource) throws Exception {
        int ipLen = isIpv6(pkt) ? IP6_ADDR_LEN : IP4_ADDR_LEN;
        int srcIpOffset = isIpv6(pkt) ? IP6_ADDR_OFFSET : IP4_ADDR_OFFSET;
        int ipOffset = shouldGetSource ? srcIpOffset : srcIpOffset + ipLen;

        ByteBuffer buffer = ByteBuffer.wrap(pkt);
        buffer.get(new byte[ipOffset]);
        byte[] ipAddrBytes = new byte[ipLen];
        buffer.get(ipAddrBytes);
        return InetAddress.getByAddress(ipAddrBytes);
    }

    private static int getPort(byte[] pkt, boolean shouldGetSource) {
        ByteBuffer buffer = ByteBuffer.wrap(pkt);
        int srcPortOffset = isIpv6(pkt) ? IP6_HDRLEN : IP4_HDRLEN;
        int portOffset = shouldGetSource ? srcPortOffset : srcPortOffset + PORT_LEN;

        buffer.get(new byte[portOffset]);
        return Short.toUnsignedInt(buffer.getShort());
    }

    private static byte[] buildIkePacket(
            InetAddress srcAddr,
            InetAddress dstAddr,
            int srcPort,
            int dstPort,
            boolean useEncap,
            byte[] ikePacket)
            throws Exception {
        if (useEncap) {
            ByteBuffer buffer = ByteBuffer.allocate(NON_ESP_MARKER_LEN + ikePacket.length);
            buffer.put(NON_ESP_MARKER);
            buffer.put(ikePacket);
            ikePacket = buffer.array();
        }

        UdpHeader udpPkt = new UdpHeader(srcPort, dstPort, new BytePayload(ikePacket));
        IpHeader ipPkt = getIpHeader(udpPkt.getProtocolId(), srcAddr, dstAddr, udpPkt);
        return ipPkt.getPacketBytes();
    }

    private static IpHeader getIpHeader(
            int protocol, InetAddress src, InetAddress dst, Payload payload) {
        if ((src instanceof Inet6Address) != (dst instanceof Inet6Address)) {
            throw new IllegalArgumentException("Invalid src/dst address combination");
        }

        if (src instanceof Inet6Address) {
            return new Ip6Header(protocol, (Inet6Address) src, (Inet6Address) dst, payload);
        } else {
            return new Ip4Header(protocol, (Inet4Address) src, (Inet4Address) dst, payload);
        }
    }
}
