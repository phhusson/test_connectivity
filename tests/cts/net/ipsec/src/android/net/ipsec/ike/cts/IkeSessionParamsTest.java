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

import static android.net.ipsec.ike.IkeSessionParams.IKE_OPTION_ACCEPT_ANY_REMOTE_ID;
import static android.net.ipsec.ike.IkeSessionParams.IkeAuthConfig;
import static android.net.ipsec.ike.IkeSessionParams.IkeAuthPskConfig;
import static android.system.OsConstants.AF_INET;
import static android.system.OsConstants.AF_INET6;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.net.ipsec.ike.IkeFqdnIdentification;
import android.net.ipsec.ike.IkeIdentification;
import android.net.ipsec.ike.IkeSaProposal;
import android.net.ipsec.ike.IkeSessionParams;
import android.net.ipsec.ike.IkeSessionParams.ConfigRequestIpv4PcscfServer;
import android.net.ipsec.ike.IkeSessionParams.ConfigRequestIpv6PcscfServer;
import android.net.ipsec.ike.IkeSessionParams.IkeConfigRequest;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@RunWith(AndroidJUnit4.class)
public final class IkeSessionParamsTest extends IkeSessionParamsTestBase {
    private static final int HARD_LIFETIME_SECONDS = (int) TimeUnit.HOURS.toSeconds(20L);
    private static final int SOFT_LIFETIME_SECONDS = (int) TimeUnit.HOURS.toSeconds(10L);
    private static final int DPD_DELAY_SECONDS = (int) TimeUnit.MINUTES.toSeconds(10L);
    private static final int[] RETRANS_TIMEOUT_MS_LIST = new int[] {500, 500, 500, 500, 500, 500};

    private static final Map<Class<? extends IkeConfigRequest>, Integer> EXPECTED_REQ_COUNT =
            new HashMap<>();
    private static final HashSet<InetAddress> EXPECTED_PCSCF_SERVERS = new HashSet<>();

    static {
        EXPECTED_REQ_COUNT.put(ConfigRequestIpv4PcscfServer.class, 3);
        EXPECTED_REQ_COUNT.put(ConfigRequestIpv6PcscfServer.class, 3);

        EXPECTED_PCSCF_SERVERS.add(PCSCF_IPV4_ADDRESS_1);
        EXPECTED_PCSCF_SERVERS.add(PCSCF_IPV4_ADDRESS_2);
        EXPECTED_PCSCF_SERVERS.add(PCSCF_IPV6_ADDRESS_1);
        EXPECTED_PCSCF_SERVERS.add(PCSCF_IPV6_ADDRESS_2);
    }

    // Arbitrary proposal and remote ID. Local ID is chosen to match the client end cert in the
    // following CL
    private static final IkeSaProposal SA_PROPOSAL =
            SaProposalTest.buildIkeSaProposalWithNormalModeCipher();
    private static final IkeIdentification LOCAL_ID = new IkeFqdnIdentification(LOCAL_HOSTNAME);
    private static final IkeIdentification REMOTE_ID = new IkeFqdnIdentification(REMOTE_HOSTNAME);

    /**
     * Create a Builder that has minimum configurations to build an IkeSessionParams.
     *
     * <p>Authentication method is arbitrarily selected. Using other method (e.g. setAuthEap) also
     * works.
     */
    private IkeSessionParams.Builder createIkeParamsBuilderMinimum() {
        return new IkeSessionParams.Builder(sContext)
                .setNetwork(sTunNetwork)
                .setServerHostname(IPV4_ADDRESS_REMOTE.getHostAddress())
                .addSaProposal(SA_PROPOSAL)
                .setLocalIdentification(LOCAL_ID)
                .setRemoteIdentification(REMOTE_ID)
                .setAuthPsk(IKE_PSK);
    }

    /**
     * Verify the minimum configurations to build an IkeSessionParams.
     *
     * @see #createIkeParamsBuilderMinimum
     */
    private void verifyIkeParamsMinimum(IkeSessionParams sessionParams) {
        assertEquals(sTunNetwork, sessionParams.getNetwork());
        assertEquals(IPV4_ADDRESS_REMOTE.getHostAddress(), sessionParams.getServerHostname());
        assertEquals(Arrays.asList(SA_PROPOSAL), sessionParams.getSaProposals());
        assertEquals(LOCAL_ID, sessionParams.getLocalIdentification());
        assertEquals(REMOTE_ID, sessionParams.getRemoteIdentification());

        IkeAuthConfig localConfig = sessionParams.getLocalAuthConfig();
        assertTrue(localConfig instanceof IkeAuthPskConfig);
        assertArrayEquals(IKE_PSK, ((IkeAuthPskConfig) localConfig).getPsk());
        IkeAuthConfig remoteConfig = sessionParams.getRemoteAuthConfig();
        assertTrue(remoteConfig instanceof IkeAuthPskConfig);
        assertArrayEquals(IKE_PSK, ((IkeAuthPskConfig) remoteConfig).getPsk());
    }

    private void verifySpecificPcscfConfigReqs(
            HashSet<InetAddress> expectedAddresses, IkeSessionParams sessionParams) {
        Set<InetAddress> resultAddresses = new HashSet<>();

        for (IkeConfigRequest req : sessionParams.getConfigurationRequests()) {
            if (req instanceof ConfigRequestIpv4PcscfServer
                    && ((ConfigRequestIpv4PcscfServer) req).getAddress() != null) {
                resultAddresses.add(((ConfigRequestIpv4PcscfServer) req).getAddress());
            } else if (req instanceof ConfigRequestIpv6PcscfServer
                    && ((ConfigRequestIpv6PcscfServer) req).getAddress() != null) {
                resultAddresses.add(((ConfigRequestIpv6PcscfServer) req).getAddress());
            }
        }

        assertEquals(expectedAddresses, resultAddresses);
    }

    @Test
    public void testBuildWithMinimumSet() throws Exception {
        IkeSessionParams sessionParams = createIkeParamsBuilderMinimum().build();

        verifyIkeParamsMinimum(sessionParams);

        // Verify default values that do not need explicit configuration. Do not do assertEquals
        // to be avoid being a change-detector test
        assertTrue(sessionParams.getHardLifetimeSeconds() > sessionParams.getSoftLifetimeSeconds());
        assertTrue(sessionParams.getSoftLifetimeSeconds() > 0);
        assertTrue(sessionParams.getDpdDelaySeconds() > 0);
        assertTrue(sessionParams.getRetransmissionTimeoutsMillis().length > 0);
        for (int timeout : sessionParams.getRetransmissionTimeoutsMillis()) {
            assertTrue(timeout > 0);
        }
        assertTrue(sessionParams.getConfigurationRequests().isEmpty());
        assertFalse(sessionParams.hasIkeOption(IKE_OPTION_ACCEPT_ANY_REMOTE_ID));
    }

    @Test
    public void testSetLifetimes() throws Exception {
        IkeSessionParams sessionParams =
                createIkeParamsBuilderMinimum()
                        .setLifetimeSeconds(HARD_LIFETIME_SECONDS, SOFT_LIFETIME_SECONDS)
                        .build();

        verifyIkeParamsMinimum(sessionParams);
        assertEquals(HARD_LIFETIME_SECONDS, sessionParams.getHardLifetimeSeconds());
        assertEquals(SOFT_LIFETIME_SECONDS, sessionParams.getSoftLifetimeSeconds());
    }

    @Test
    public void testSetDpdDelay() throws Exception {
        IkeSessionParams sessionParams =
                createIkeParamsBuilderMinimum().setDpdDelaySeconds(DPD_DELAY_SECONDS).build();

        verifyIkeParamsMinimum(sessionParams);
        assertEquals(DPD_DELAY_SECONDS, sessionParams.getDpdDelaySeconds());
    }

    @Test
    public void testSetRetransmissionTimeouts() throws Exception {
        IkeSessionParams sessionParams =
                createIkeParamsBuilderMinimum()
                        .setRetransmissionTimeoutsMillis(RETRANS_TIMEOUT_MS_LIST)
                        .build();

        verifyIkeParamsMinimum(sessionParams);
        assertArrayEquals(RETRANS_TIMEOUT_MS_LIST, sessionParams.getRetransmissionTimeoutsMillis());
    }

    @Test
    public void testSetPcscfConfigRequests() throws Exception {
        IkeSessionParams sessionParams =
                createIkeParamsBuilderMinimum()
                        .setRetransmissionTimeoutsMillis(RETRANS_TIMEOUT_MS_LIST)
                        .addPcscfServerRequest(AF_INET)
                        .addPcscfServerRequest(PCSCF_IPV4_ADDRESS_1)
                        .addPcscfServerRequest(PCSCF_IPV6_ADDRESS_1)
                        .addPcscfServerRequest(AF_INET6)
                        .addPcscfServerRequest(PCSCF_IPV4_ADDRESS_2)
                        .addPcscfServerRequest(PCSCF_IPV6_ADDRESS_2)
                        .build();

        verifyIkeParamsMinimum(sessionParams);
        verifyConfigRequestTypes(EXPECTED_REQ_COUNT, sessionParams.getConfigurationRequests());

        Set<InetAddress> resultAddresses = new HashSet<>();
        for (IkeConfigRequest req : sessionParams.getConfigurationRequests()) {
            if (req instanceof ConfigRequestIpv4PcscfServer
                    && ((ConfigRequestIpv4PcscfServer) req).getAddress() != null) {
                resultAddresses.add(((ConfigRequestIpv4PcscfServer) req).getAddress());
            } else if (req instanceof ConfigRequestIpv6PcscfServer
                    && ((ConfigRequestIpv6PcscfServer) req).getAddress() != null) {
                resultAddresses.add(((ConfigRequestIpv6PcscfServer) req).getAddress());
            }
        }
        assertEquals(EXPECTED_PCSCF_SERVERS, resultAddresses);
    }

    @Test
    public void testAddIkeOption() throws Exception {
        IkeSessionParams sessionParams =
                createIkeParamsBuilderMinimum()
                        .addIkeOption(IKE_OPTION_ACCEPT_ANY_REMOTE_ID)
                        .build();

        verifyIkeParamsMinimum(sessionParams);
        assertTrue(sessionParams.hasIkeOption(IKE_OPTION_ACCEPT_ANY_REMOTE_ID));
    }

    @Test
    public void testRemoveIkeOption() throws Exception {
        IkeSessionParams sessionParams =
                createIkeParamsBuilderMinimum()
                        .addIkeOption(IKE_OPTION_ACCEPT_ANY_REMOTE_ID)
                        .removeIkeOption(IKE_OPTION_ACCEPT_ANY_REMOTE_ID)
                        .build();

        verifyIkeParamsMinimum(sessionParams);
        assertFalse(sessionParams.hasIkeOption(IKE_OPTION_ACCEPT_ANY_REMOTE_ID));
    }

    @Test
    public void testBuildWithPsk() throws Exception {
        IkeSessionParams sessionParams =
                new IkeSessionParams.Builder(sContext)
                        .setNetwork(sTunNetwork)
                        .setServerHostname(IPV4_ADDRESS_REMOTE.getHostAddress())
                        .addSaProposal(SA_PROPOSAL)
                        .setLocalIdentification(LOCAL_ID)
                        .setRemoteIdentification(REMOTE_ID)
                        .setAuthPsk(IKE_PSK)
                        .build();
        assertEquals(sTunNetwork, sessionParams.getNetwork());
        assertEquals(IPV4_ADDRESS_REMOTE.getHostAddress(), sessionParams.getServerHostname());
        assertEquals(Arrays.asList(SA_PROPOSAL), sessionParams.getSaProposals());
        assertEquals(LOCAL_ID, sessionParams.getLocalIdentification());
        assertEquals(REMOTE_ID, sessionParams.getRemoteIdentification());

        IkeAuthConfig localConfig = sessionParams.getLocalAuthConfig();
        assertTrue(localConfig instanceof IkeAuthPskConfig);
        assertArrayEquals(IKE_PSK, ((IkeAuthPskConfig) localConfig).getPsk());
        IkeAuthConfig remoteConfig = sessionParams.getRemoteAuthConfig();
        assertTrue(remoteConfig instanceof IkeAuthPskConfig);
        assertArrayEquals(IKE_PSK, ((IkeAuthPskConfig) remoteConfig).getPsk());
    }

    // TODO(b/148689509): Add tests for building IkeSessionParams using EAP and
    // digital-signature-based authentication
}
