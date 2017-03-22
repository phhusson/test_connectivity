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

package android.net.wifi.cts;

import android.net.wifi.hotspot2.PasspointConfiguration;
import android.net.wifi.hotspot2.omadm.PpsMoParser;
import android.net.wifi.hotspot2.pps.Credential;
import android.net.wifi.hotspot2.pps.HomeSp;
import android.net.wifi.hotspot2.pps.Policy;
import android.net.wifi.hotspot2.pps.UpdateParameter;
import android.test.AndroidTestCase;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CTS tests for PPS MO (PerProviderSubscription Management Object) XML string parsing API.
 */
public class PpsMoParserTest extends AndroidTestCase {
    private static final String PPS_MO_XML_FILE = "assets/PerProviderSubscription.xml";

    /**
     * Read the content of the given resource file into a String.
     *
     * @param filename String name of the file
     * @return String
     * @throws IOException
     */
    private String loadResourceFile(String filename) throws IOException {
        InputStream in = getClass().getClassLoader().getResourceAsStream(filename);
        BufferedReader reader = new BufferedReader(new InputStreamReader(in));
        StringBuilder builder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            builder.append(line).append("\n");
        }
        return builder.toString();
    }

    /**
     * Generate a {@link PasspointConfiguration} that matches the configuration specified in the
     * XML file {@link #PPS_MO_XML_FILE}.
     *
     * @return {@link PasspointConfiguration}
     */
    private PasspointConfiguration generateConfigurationFromPPSMOTree() throws Exception {
        DateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        byte[] certFingerprint = new byte[32];
        Arrays.fill(certFingerprint, (byte) 0x1f);

        PasspointConfiguration config = new PasspointConfiguration();
        config.setUpdateIdentifier(12);
        assertEquals(12, config.getUpdateIdentifier());
        config.setCredentialPriority(99);
        assertEquals(99, config.getCredentialPriority());

        // AAA Server trust root.
        Map<String, byte[]> trustRootCertList = new HashMap<>();
        trustRootCertList.put("server1.trust.root.com", certFingerprint);
        config.setTrustRootCertList(trustRootCertList);
        assertEquals(trustRootCertList, config.getTrustRootCertList());

        // Subscription update.
        UpdateParameter subscriptionUpdate = new UpdateParameter();
        subscriptionUpdate.setUpdateIntervalInMinutes(120);
        assertEquals(120, subscriptionUpdate.getUpdateIntervalInMinutes());
        subscriptionUpdate.setUpdateMethod(UpdateParameter.UPDATE_METHOD_SSP);
        assertEquals(UpdateParameter.UPDATE_METHOD_SSP, subscriptionUpdate.getUpdateMethod());
        subscriptionUpdate.setRestriction(UpdateParameter.UPDATE_RESTRICTION_ROAMING_PARTNER);
        assertEquals(UpdateParameter.UPDATE_RESTRICTION_ROAMING_PARTNER,
                subscriptionUpdate.getRestriction());
        subscriptionUpdate.setServerUri("subscription.update.com");
        assertEquals("subscription.update.com", subscriptionUpdate.getServerUri());
        subscriptionUpdate.setUsername("subscriptionUser");
        assertEquals("subscriptionUser", subscriptionUpdate.getUsername());
        subscriptionUpdate.setBase64EncodedPassword("subscriptionPass");
        assertEquals("subscriptionPass", subscriptionUpdate.getBase64EncodedPassword());
        subscriptionUpdate.setTrustRootCertUrl("subscription.update.cert.com");
        assertEquals("subscription.update.cert.com", subscriptionUpdate.getTrustRootCertUrl());
        subscriptionUpdate.setTrustRootCertSha256Fingerprint(certFingerprint);
        assertTrue(Arrays.equals(certFingerprint,
                subscriptionUpdate.getTrustRootCertSha256Fingerprint()));
        config.setSubscriptionUpdate(subscriptionUpdate);
        assertEquals(subscriptionUpdate, config.getSubscriptionUpdate());

        // Subscription parameters.
        config.setSubscriptionCreationTimeInMs(format.parse("2016-02-01T10:00:00Z").getTime());
        assertEquals(format.parse("2016-02-01T10:00:00Z").getTime(),
                config.getSubscriptionCreationTimeInMs());
        config.setSubscriptionExpirationTimeInMs(format.parse("2016-03-01T10:00:00Z").getTime());
        assertEquals(format.parse("2016-03-01T10:00:00Z").getTime(),
                config.getSubscriptionExpirationTimeInMs());
        config.setSubscriptionType("Gold");
        assertEquals("Gold", config.getSubscriptionType());
        config.setUsageLimitDataLimit(921890);
        assertEquals(921890, config.getUsageLimitDataLimit());
        config.setUsageLimitStartTimeInMs(format.parse("2016-12-01T10:00:00Z").getTime());
        assertEquals(format.parse("2016-12-01T10:00:00Z").getTime(),
                config.getUsageLimitStartTimeInMs());
        config.setUsageLimitTimeLimitInMinutes(120);
        assertEquals(120, config.getUsageLimitTimeLimitInMinutes());
        config.setUsageLimitUsageTimePeriodInMinutes(99910);
        assertEquals(99910, config.getUsageLimitUsageTimePeriodInMinutes());

        // HomeSP configuration.
        HomeSp homeSp = new HomeSp();
        homeSp.setFriendlyName("Century House");
        assertEquals("Century House", homeSp.getFriendlyName());
        homeSp.setFqdn("mi6.co.uk");
        assertEquals("mi6.co.uk", homeSp.getFqdn());
        homeSp.setRoamingConsortiumOis(new long[] {0x112233L, 0x445566L});
        assertTrue(Arrays.equals(new long[] {0x112233L, 0x445566L},
                homeSp.getRoamingConsortiumOis()));
        homeSp.setIconUrl("icon.test.com");
        assertEquals("icon.test.com", homeSp.getIconUrl());
        Map<String, Long> homeNetworkIds = new HashMap<>();
        homeNetworkIds.put("TestSSID", 0x12345678L);
        homeNetworkIds.put("NullHESSID", null);
        homeSp.setHomeNetworkIds(homeNetworkIds);
        assertEquals(homeNetworkIds, homeSp.getHomeNetworkIds());
        homeSp.setMatchAllOis(new long[] {0x11223344});
        assertTrue(Arrays.equals(new long[] {0x11223344}, homeSp.getMatchAllOis()));
        homeSp.setMatchAnyOis(new long[] {0x55667788});
        assertTrue(Arrays.equals(new long[] {0x55667788}, homeSp.getMatchAnyOis()));
        homeSp.setOtherHomePartners(new String[] {"other.fqdn.com"});
        assertTrue(Arrays.equals(new String[] {"other.fqdn.com"},
                homeSp.getOtherHomePartners()));
        config.setHomeSp(homeSp);
        assertEquals(homeSp, config.getHomeSp());

        // Credential configuration.
        Credential credential = new Credential();
        credential.setCreationTimeInMs(format.parse("2016-01-01T10:00:00Z").getTime());
        assertEquals(format.parse("2016-01-01T10:00:00Z").getTime(),
                credential.getCreationTimeInMs());
        credential.setExpirationTimeInMs(format.parse("2016-02-01T10:00:00Z").getTime());
        assertEquals(format.parse("2016-02-01T10:00:00Z").getTime(),
                credential.getExpirationTimeInMs());
        credential.setRealm("shaken.stirred.com");
        assertEquals("shaken.stirred.com", credential.getRealm());
        credential.setCheckAaaServerCertStatus(true);
        assertTrue(credential.getCheckAaaServerCertStatus());
        Credential.UserCredential userCredential = new Credential.UserCredential();
        userCredential.setUsername("james");
        assertEquals("james", userCredential.getUsername());
        userCredential.setPassword("Ym9uZDAwNw==");
        assertEquals("Ym9uZDAwNw==", userCredential.getPassword());
        userCredential.setMachineManaged(true);
        assertTrue(userCredential.getMachineManaged());
        userCredential.setSoftTokenApp("TestApp");
        assertEquals("TestApp", userCredential.getSoftTokenApp());
        userCredential.setAbleToShare(true);
        assertTrue(userCredential.getAbleToShare());
        userCredential.setEapType(21);
        assertEquals(21, userCredential.getEapType());
        userCredential.setNonEapInnerMethod("MS-CHAP-V2");
        assertEquals("MS-CHAP-V2", userCredential.getNonEapInnerMethod());
        credential.setUserCredential(userCredential);
        assertEquals(userCredential, credential.getUserCredential());
        Credential.CertificateCredential certCredential = new Credential.CertificateCredential();
        certCredential.setCertType("x509v3");
        assertEquals("x509v3", certCredential.getCertType());
        certCredential.setCertSha256Fingerprint(certFingerprint);
        assertTrue(Arrays.equals(certFingerprint, certCredential.getCertSha256Fingerprint()));
        credential.setCertCredential(certCredential);
        assertEquals(certCredential, credential.getCertCredential());
        Credential.SimCredential simCredential = new Credential.SimCredential();
        simCredential.setImsi("imsi");
        assertEquals("imsi", simCredential.getImsi());
        simCredential.setEapType(24);
        assertEquals(24, simCredential.getEapType());
        credential.setSimCredential(simCredential);
        assertEquals(simCredential, credential.getSimCredential());
        config.setCredential(credential);
        assertEquals(credential, config.getCredential());

        // Policy configuration.
        Policy policy = new Policy();
        List<Policy.RoamingPartner> preferredRoamingPartnerList = new ArrayList<>();
        Policy.RoamingPartner partner1 = new Policy.RoamingPartner();
        partner1.setFqdn("test1.fqdn.com");
        assertEquals("test1.fqdn.com", partner1.getFqdn());
        partner1.setFqdnExactMatch(true);
        assertTrue(partner1.getFqdnExactMatch());
        partner1.setPriority(127);
        assertEquals(127, partner1.getPriority());
        partner1.setCountries("us,fr");
        assertEquals("us,fr", partner1.getCountries());
        Policy.RoamingPartner partner2 = new Policy.RoamingPartner();
        partner2.setFqdn("test2.fqdn.com");
        assertEquals("test2.fqdn.com", partner2.getFqdn());
        partner2.setFqdnExactMatch(false);
        assertFalse(partner2.getFqdnExactMatch());
        partner2.setPriority(200);
        assertEquals(200, partner2.getPriority());
        partner2.setCountries("*");
        assertEquals("*", partner2.getCountries());
        preferredRoamingPartnerList.add(partner1);
        preferredRoamingPartnerList.add(partner2);
        policy.setPreferredRoamingPartnerList(preferredRoamingPartnerList);
        assertEquals(preferredRoamingPartnerList, policy.getPreferredRoamingPartnerList());
        policy.setMinHomeDownlinkBandwidth(23412);
        assertEquals(23412, policy.getMinHomeDownlinkBandwidth());
        policy.setMinHomeUplinkBandwidth(9823);
        assertEquals(9823, policy.getMinHomeUplinkBandwidth());
        policy.setMinRoamingDownlinkBandwidth(9271);
        assertEquals(9271, policy.getMinRoamingDownlinkBandwidth());
        policy.setMinRoamingUplinkBandwidth(2315);
        assertEquals(2315, policy.getMinRoamingUplinkBandwidth());
        policy.setExcludedSsidList(new String[] {"excludeSSID"});
        assertTrue(Arrays.equals(new String[] {"excludeSSID"}, policy.getExcludedSsidList()));
        Map<Integer, String> requiredProtoPortMap = new HashMap<>();
        requiredProtoPortMap.put(12, "34,92,234");
        policy.setRequiredProtoPortMap(requiredProtoPortMap);
        assertEquals(requiredProtoPortMap, policy.getRequiredProtoPortMap());
        policy.setMaximumBssLoadValue(23);
        assertEquals(23, policy.getMaximumBssLoadValue());
        UpdateParameter policyUpdate = new UpdateParameter();
        policyUpdate.setUpdateIntervalInMinutes(120);
        assertEquals(120, policyUpdate.getUpdateIntervalInMinutes());
        policyUpdate.setUpdateMethod(UpdateParameter.UPDATE_METHOD_OMADM);
        assertEquals(UpdateParameter.UPDATE_METHOD_OMADM, policyUpdate.getUpdateMethod());
        policyUpdate.setRestriction(UpdateParameter.UPDATE_RESTRICTION_HOMESP);
        assertEquals(UpdateParameter.UPDATE_RESTRICTION_HOMESP, policyUpdate.getRestriction());
        policyUpdate.setServerUri("policy.update.com");
        assertEquals("policy.update.com", policyUpdate.getServerUri());
        policyUpdate.setUsername("updateUser");
        assertEquals("updateUser", policyUpdate.getUsername());
        policyUpdate.setBase64EncodedPassword("updatePass");
        assertEquals("updatePass", policyUpdate.getBase64EncodedPassword());
        policyUpdate.setTrustRootCertUrl("update.cert.com");
        assertEquals("update.cert.com", policyUpdate.getTrustRootCertUrl());
        policyUpdate.setTrustRootCertSha256Fingerprint(certFingerprint);
        assertTrue(Arrays.equals(certFingerprint,
                policyUpdate.getTrustRootCertSha256Fingerprint()));
        policy.setPolicyUpdate(policyUpdate);
        assertEquals(policyUpdate, policy.getPolicyUpdate());
        config.setPolicy(policy);
        assertEquals(policy, config.getPolicy());
        return config;
    }

    /**
     * Parse and verify all supported fields under PPS MO tree.
     *
     * @throws Exception
     */
    public void testParsePPSMOTree() throws Exception {
        String ppsMoTree = loadResourceFile(PPS_MO_XML_FILE);
        PasspointConfiguration expectedConfig = generateConfigurationFromPPSMOTree();
        PasspointConfiguration actualConfig = PpsMoParser.parseMoText(ppsMoTree);
        assertTrue(actualConfig.equals(expectedConfig));
    }
}
