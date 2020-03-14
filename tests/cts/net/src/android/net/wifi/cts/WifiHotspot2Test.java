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

package android.net.wifi.cts;

import static android.net.wifi.WifiConfiguration.METERED_OVERRIDE_NONE;

import android.net.wifi.hotspot2.PasspointConfiguration;
import android.net.wifi.hotspot2.pps.Credential;
import android.net.wifi.hotspot2.pps.HomeSp;
import android.test.AndroidTestCase;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class WifiHotspot2Test extends AndroidTestCase {
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Tests {@link PasspointConfiguration#getMeteredOverride()} method.
     *
     * Test default value
     */
    public void testGetMeteredOverride() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        PasspointConfiguration passpointConfiguration = new PasspointConfiguration();
        assertEquals(METERED_OVERRIDE_NONE, passpointConfiguration.getMeteredOverride());
    }

    /**
     * Tests {@link PasspointConfiguration#getSubscriptionExpirationTimeMillis()} method.
     *
     * Test default value
     */
    public void testGetSubscriptionExpirationTimeMillis() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        PasspointConfiguration passpointConfiguration = new PasspointConfiguration();
        assertEquals(Long.MIN_VALUE,
                passpointConfiguration.getSubscriptionExpirationTimeMillis());
    }

    /**
     * Tests {@link PasspointConfiguration#getUniqueId()} method.
     *
     * Test unique identifier is not null
     */
    public void testGetUniqueId() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        PasspointConfiguration passpointConfiguration = createConfig();
        assertNotNull(passpointConfiguration.getUniqueId());
    }

    /**
     * Tests {@link PasspointConfiguration#isAutojoinEnabled()} method.
     *
     * Test default value
     */
    public void testIsAutojoinEnabled() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        PasspointConfiguration passpointConfiguration = new PasspointConfiguration();
        assertTrue(passpointConfiguration.isAutojoinEnabled());
    }

    /**
     * Tests {@link PasspointConfiguration#isMacRandomizationEnabled()} method.
     *
     * Test default value
     */
    public void testIsMacRandomizationEnabled() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        PasspointConfiguration passpointConfiguration = new PasspointConfiguration();
        assertTrue(passpointConfiguration.isMacRandomizationEnabled());
    }

    /**
     * Tests {@link PasspointConfiguration#isOsuProvisioned()} method.
     *
     * Test default value
     */
    public void testIsOsuProvisioned() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        PasspointConfiguration passpointConfiguration = createConfig();
        assertFalse(passpointConfiguration.isOsuProvisioned());
    }

    /**
     * Tests {@link PasspointConfiguration#PasspointConfiguration(PasspointConfiguration)} method.
     *
     * Test the PasspointConfiguration copy constructor
     */
    public void testPasspointConfigurationCopyConstructor() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        PasspointConfiguration passpointConfiguration = createConfig();
        PasspointConfiguration copyOfPasspointConfiguration =
                new PasspointConfiguration(passpointConfiguration);
        assertEquals(passpointConfiguration, copyOfPasspointConfiguration);
    }

    /**
     * Tests {@link HomeSp#HomeSp(HomeSp)} method.
     *
     * Test the HomeSp copy constructor
     */
    public void testHomeSpCopyConstructor() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        HomeSp homeSp = createHomeSp();
        HomeSp copyOfHomeSp = new HomeSp(homeSp);
        assertEquals(copyOfHomeSp, homeSp);
    }

    /**
     * Tests {@link Credential#Credential(Credential)} method.
     *
     * Test the Credential copy constructor
     */
    public void testCredentialCopyConstructor() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        Credential credential = createCredential();
        Credential copyOfCredential = new Credential(credential);
        assertEquals(copyOfCredential, credential);
    }

    /**
     * Tests {@link Credential.UserCredential#UserCredential(Credential.UserCredential)} method.
     *
     * Test the Credential.UserCredential copy constructor
     */
    public void testUserCredentialCopyConstructor() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        Credential.UserCredential userCredential = new Credential.UserCredential();
        userCredential.setUsername("username");
        userCredential.setPassword("password");
        userCredential.setEapType(21 /* EAP_TTLS */);
        userCredential.setNonEapInnerMethod("MS-CHAP");

        Credential.UserCredential copyOfUserCredential =
                new Credential.UserCredential(userCredential);
        assertEquals(copyOfUserCredential, userCredential);
    }

    /**
     * Tests {@link Credential.CertificateCredential#CertificateCredential(Credential.CertificateCredential)}
     * method.
     *
     * Test the Credential.CertificateCredential copy constructor
     */
    public void testCertCredentialCopyConstructor() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        Credential.CertificateCredential certCredential = new Credential.CertificateCredential();
        certCredential.setCertType("x509v3");

        Credential.CertificateCredential copyOfCertificateCredential =
                new Credential.CertificateCredential(certCredential);
        assertEquals(copyOfCertificateCredential, certCredential);
    }

    /**
     * Tests {@link Credential.SimCredential#SimCredential(Credential.SimCredential)}
     * method.
     *
     * Test the Credential.SimCredential copy constructor
     */
    public void testSimCredentialCopyConstructor() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        Credential.SimCredential simCredential = new Credential.SimCredential();
        simCredential.setImsi("1234*");
        simCredential.setEapType(18/* EAP_SIM */);

        Credential.SimCredential copyOfSimCredential = new Credential.SimCredential(simCredential);
        assertEquals(copyOfSimCredential, simCredential);
    }

    /**
     * Tests {@link Credential#getCaCertificate()}  method.
     *
     * Test that getting a set certificate produces the same value
     */
    public void testCredentialGetCertificate() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        Credential credential = new Credential();
        credential.setCaCertificate(FakeKeys.CA_CERT0);

        assertEquals(FakeKeys.CA_CERT0, credential.getCaCertificate());
    }

    /**
     * Tests {@link Credential#getClientCertificateChain()} and
     * {@link Credential#setCaCertificates(X509Certificate[])} methods.
     *
     * Test that getting a set client certificate chain produces the same value
     */
    public void testCredentialClientCertificateChain() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        Credential credential = new Credential();
        X509Certificate[] certificates = new X509Certificate[] {FakeKeys.CLIENT_CERT};
        credential.setClientCertificateChain(certificates);

        assertTrue(Arrays.equals(certificates, credential.getClientCertificateChain()));
    }

    /**
     * Tests {@link Credential#getClientPrivateKey()} and
     * {@link Credential#setClientPrivateKey(PrivateKey)} methods.
     *
     * Test that getting a set client private key produces the same value
     */
    public void testCredentialSetGetClientPrivateKey() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        Credential credential = new Credential();
        credential.setClientPrivateKey(FakeKeys.RSA_KEY1);

        assertEquals(FakeKeys.RSA_KEY1, credential.getClientPrivateKey());
    }

    /**
     * Tests {@link Credential#getClientPrivateKey()} and
     * {@link Credential#setClientPrivateKey(PrivateKey)} methods.
     *
     * Test that getting a set client private key produces the same value
     */
    public void testCredentialGetClientPrivateKey() throws Exception {
        if (!WifiFeature.isWifiSupported(getContext())) {
            // skip the test if WiFi is not supported
            return;
        }
        Credential credential = new Credential();
        credential.setClientPrivateKey(FakeKeys.RSA_KEY1);

        assertEquals(FakeKeys.RSA_KEY1, credential.getClientPrivateKey());
    }

    private static PasspointConfiguration createConfig() {
        PasspointConfiguration config = new PasspointConfiguration();
        config.setHomeSp(createHomeSp());
        config.setCredential(createCredential());
        return config;
    }

    private static HomeSp createHomeSp() {
        HomeSp homeSp = new HomeSp();
        homeSp.setFqdn("test.com");
        homeSp.setFriendlyName("friendly name");
        homeSp.setRoamingConsortiumOis(new long[] {0x55, 0x66});
        return homeSp;
    }

    private static Credential createCredential() {
        Credential cred = new Credential();
        cred.setRealm("realm");
        cred.setUserCredential(null);
        cred.setCertCredential(null);
        cred.setSimCredential(new Credential.SimCredential());
        cred.getSimCredential().setImsi("1234*");
        cred.getSimCredential().setEapType(18/* EAP_SIM */);
        cred.setCaCertificate(null);
        cred.setClientCertificateChain(null);
        cred.setClientPrivateKey(null);
        return cred;
    }
}
