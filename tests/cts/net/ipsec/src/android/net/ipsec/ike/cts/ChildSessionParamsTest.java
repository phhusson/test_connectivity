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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.net.ipsec.ike.ChildSaProposal;
import android.net.ipsec.ike.ChildSessionParams;
import android.net.ipsec.ike.TransportModeChildSessionParams;
import android.net.ipsec.ike.TunnelModeChildSessionParams;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@RunWith(AndroidJUnit4.class)
public class ChildSessionParamsTest extends IkeTestBase {
    private static final int HARD_LIFETIME_SECONDS = (int) TimeUnit.HOURS.toSeconds(3L);
    private static final int SOFT_LIFETIME_SECONDS = (int) TimeUnit.HOURS.toSeconds(1L);

    // Random proposal. Content doesn't matter
    private final ChildSaProposal mSaProposal =
            SaProposalTest.buildChildSaProposalWithCombinedModeCipher();

    private void verifyTunnelModeChildParamsWithDefaultValues(ChildSessionParams childParams) {
        assertTrue(childParams instanceof TunnelModeChildSessionParams);
        verifyChildParamsWithDefaultValues(childParams);
    }

    private void verifyTunnelModeChildParamsWithCustomizedValues(ChildSessionParams childParams) {
        assertTrue(childParams instanceof TunnelModeChildSessionParams);
        verifyChildParamsWithCustomizedValues(childParams);
    }

    private void verifyTransportModeChildParamsWithDefaultValues(ChildSessionParams childParams) {
        assertTrue(childParams instanceof TransportModeChildSessionParams);
        verifyChildParamsWithDefaultValues(childParams);
    }

    private void verifyTransportModeChildParamsWithCustomizedValues(
            ChildSessionParams childParams) {
        assertTrue(childParams instanceof TransportModeChildSessionParams);
        verifyChildParamsWithCustomizedValues(childParams);
    }

    private void verifyChildParamsWithDefaultValues(ChildSessionParams childParams) {
        assertEquals(Arrays.asList(mSaProposal), childParams.getSaProposals());

        // Do not do assertEquals to the default values to be avoid being a change-detector test
        assertTrue(childParams.getHardLifetimeSeconds() > childParams.getSoftLifetimeSeconds());
        assertTrue(childParams.getSoftLifetimeSeconds() > 0);

        assertEquals(
                Arrays.asList(DEFAULT_V4_TS, DEFAULT_V6_TS),
                childParams.getInboundTrafficSelectors());
        assertEquals(
                Arrays.asList(DEFAULT_V4_TS, DEFAULT_V6_TS),
                childParams.getOutboundTrafficSelectors());
    }

    private void verifyChildParamsWithCustomizedValues(ChildSessionParams childParams) {
        assertEquals(Arrays.asList(mSaProposal), childParams.getSaProposals());

        assertEquals(HARD_LIFETIME_SECONDS, childParams.getHardLifetimeSeconds());
        assertEquals(SOFT_LIFETIME_SECONDS, childParams.getSoftLifetimeSeconds());

        assertEquals(
                Arrays.asList(INBOUND_V4_TS, INBOUND_V6_TS),
                childParams.getInboundTrafficSelectors());
        assertEquals(
                Arrays.asList(OUTBOUND_V4_TS, OUTBOUND_V6_TS),
                childParams.getOutboundTrafficSelectors());
    }

    @Test
    public void testBuildTransportModeParamsWithDefaultValues() {
        TransportModeChildSessionParams childParams =
                new TransportModeChildSessionParams.Builder().addSaProposal(mSaProposal).build();

        verifyTransportModeChildParamsWithDefaultValues(childParams);
    }

    @Test
    public void testBuildTunnelModeParamsWithDefaultValues() {
        TunnelModeChildSessionParams childParams =
                new TunnelModeChildSessionParams.Builder().addSaProposal(mSaProposal).build();

        verifyTunnelModeChildParamsWithDefaultValues(childParams);
        assertTrue(childParams.getConfigurationRequests().isEmpty());
    }

    @Test
    public void testBuildTransportModeParamsWithCustomizedValues() {
        TransportModeChildSessionParams childParams =
                new TransportModeChildSessionParams.Builder()
                        .addSaProposal(mSaProposal)
                        .setLifetimeSeconds(HARD_LIFETIME_SECONDS, SOFT_LIFETIME_SECONDS)
                        .addInboundTrafficSelectors(INBOUND_V4_TS)
                        .addInboundTrafficSelectors(INBOUND_V6_TS)
                        .addOutboundTrafficSelectors(OUTBOUND_V4_TS)
                        .addOutboundTrafficSelectors(OUTBOUND_V6_TS)
                        .build();

        verifyTransportModeChildParamsWithCustomizedValues(childParams);
    }

    @Test
    public void testBuildTunnelModeParamsWithCustomizedValues() {
        TunnelModeChildSessionParams childParams =
                new TunnelModeChildSessionParams.Builder()
                        .addSaProposal(mSaProposal)
                        .setLifetimeSeconds(HARD_LIFETIME_SECONDS, SOFT_LIFETIME_SECONDS)
                        .addInboundTrafficSelectors(INBOUND_V4_TS)
                        .addInboundTrafficSelectors(INBOUND_V6_TS)
                        .addOutboundTrafficSelectors(OUTBOUND_V4_TS)
                        .addOutboundTrafficSelectors(OUTBOUND_V6_TS)
                        .build();

        verifyTunnelModeChildParamsWithCustomizedValues(childParams);
    }
}
