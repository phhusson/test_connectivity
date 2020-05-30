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

package android.net.cts;

import static com.android.compatibility.common.util.SystemUtil.runWithShellPermissionIdentity;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import android.Manifest;
import android.annotation.NonNull;
import android.app.AppOpsManager;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Ikev2VpnProfile;
import android.net.IpSecAlgorithm;
import android.net.ProxyInfo;
import android.net.VpnManager;
import android.net.cts.util.CtsNetUtils;
import android.platform.test.annotations.AppModeFull;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import com.android.org.bouncycastle.x509.X509V1CertificateGenerator;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

@RunWith(AndroidJUnit4.class)
@AppModeFull(reason = "Appops state changes disallowed for instant apps (OP_ACTIVATE_PLATFORM_VPN)")
public class Ikev2VpnTest {
    private static final String TAG = Ikev2VpnTest.class.getSimpleName();

    private static final String TEST_SERVER_ADDR = "2001:db8::1";
    private static final String TEST_IDENTITY = "client.cts.android.com";
    private static final List<String> TEST_ALLOWED_ALGORITHMS =
            Arrays.asList(IpSecAlgorithm.AUTH_CRYPT_AES_GCM);

    private static final ProxyInfo TEST_PROXY_INFO =
            ProxyInfo.buildDirectProxy("proxy.cts.android.com", 1234);
    private static final int TEST_MTU = 1300;

    private static final byte[] TEST_PSK = "ikev2".getBytes();
    private static final String TEST_USER = "username";
    private static final String TEST_PASSWORD = "pa55w0rd";

    // Static state to reduce setup/teardown
    private static final Context sContext = InstrumentationRegistry.getContext();
    private static final ConnectivityManager sCM =
            (ConnectivityManager) sContext.getSystemService(Context.CONNECTIVITY_SERVICE);
    private static final VpnManager sVpnMgr =
            (VpnManager) sContext.getSystemService(Context.VPN_MANAGEMENT_SERVICE);
    private static final CtsNetUtils mCtsNetUtils = new CtsNetUtils(sContext);

    private final X509Certificate mServerRootCa;
    private final CertificateAndKey mUserCertKey;

    public Ikev2VpnTest() throws Exception {
        // Build certificates
        mServerRootCa = generateRandomCertAndKeyPair().cert;
        mUserCertKey = generateRandomCertAndKeyPair();
    }

    /**
     * Sets the given appop using shell commands
     *
     * <p>This method must NEVER be called from within a shell permission, as it will attempt to
     * acquire, and then drop the shell permission identity. This results in the caller losing the
     * shell permission identity due to these calls not being reference counted.
     */
    public void setAppop(int appop, boolean allow) {
        // Requires shell permission to update appops.
        runWithShellPermissionIdentity(() -> {
            mCtsNetUtils.setAppopPrivileged(appop, allow);
        }, Manifest.permission.MANAGE_TEST_NETWORKS);
    }

    private Ikev2VpnProfile buildIkev2VpnProfileCommon(
            Ikev2VpnProfile.Builder builder, boolean isRestrictedToTestNetworks) throws Exception {
        if (isRestrictedToTestNetworks) {
            builder.restrictToTestNetworks();
        }

        return builder.setBypassable(true)
                .setProxy(TEST_PROXY_INFO)
                .setMaxMtu(TEST_MTU)
                .setMetered(false)
                .setAllowedAlgorithms(TEST_ALLOWED_ALGORITHMS)
                .build();
    }

    private Ikev2VpnProfile buildIkev2VpnProfilePsk(boolean isRestrictedToTestNetworks)
            throws Exception {
        final Ikev2VpnProfile.Builder builder =
                new Ikev2VpnProfile.Builder(TEST_SERVER_ADDR, TEST_IDENTITY).setAuthPsk(TEST_PSK);

        return buildIkev2VpnProfileCommon(builder, isRestrictedToTestNetworks);
    }

    private Ikev2VpnProfile buildIkev2VpnProfileUsernamePassword(boolean isRestrictedToTestNetworks)
            throws Exception {
        final Ikev2VpnProfile.Builder builder =
                new Ikev2VpnProfile.Builder(TEST_SERVER_ADDR, TEST_IDENTITY)
                        .setAuthUsernamePassword(TEST_USER, TEST_PASSWORD, mServerRootCa);

        return buildIkev2VpnProfileCommon(builder, isRestrictedToTestNetworks);
    }

    private Ikev2VpnProfile buildIkev2VpnProfileDigitalSignature(boolean isRestrictedToTestNetworks)
            throws Exception {
        final Ikev2VpnProfile.Builder builder =
                new Ikev2VpnProfile.Builder(TEST_SERVER_ADDR, TEST_IDENTITY)
                        .setAuthDigitalSignature(
                                mUserCertKey.cert, mUserCertKey.key, mServerRootCa);

        return buildIkev2VpnProfileCommon(builder, isRestrictedToTestNetworks);
    }

    private void checkBasicIkev2VpnProfile(@NonNull Ikev2VpnProfile profile) throws Exception {
        assertEquals(TEST_SERVER_ADDR, profile.getServerAddr());
        assertEquals(TEST_IDENTITY, profile.getUserIdentity());
        assertEquals(TEST_PROXY_INFO, profile.getProxyInfo());
        assertEquals(TEST_ALLOWED_ALGORITHMS, profile.getAllowedAlgorithms());
        assertTrue(profile.isBypassable());
        assertFalse(profile.isMetered());
        assertEquals(TEST_MTU, profile.getMaxMtu());
        assertFalse(profile.isRestrictedToTestNetworks());
    }

    @Test
    public void testBuildIkev2VpnProfilePsk() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        final Ikev2VpnProfile profile =
                buildIkev2VpnProfilePsk(false /* isRestrictedToTestNetworks */);

        checkBasicIkev2VpnProfile(profile);
        assertArrayEquals(TEST_PSK, profile.getPresharedKey());

        // Verify nothing else is set.
        assertNull(profile.getUsername());
        assertNull(profile.getPassword());
        assertNull(profile.getServerRootCaCert());
        assertNull(profile.getRsaPrivateKey());
        assertNull(profile.getUserCert());
    }

    @Test
    public void testBuildIkev2VpnProfileUsernamePassword() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        final Ikev2VpnProfile profile =
                buildIkev2VpnProfileUsernamePassword(false /* isRestrictedToTestNetworks */);

        checkBasicIkev2VpnProfile(profile);
        assertEquals(TEST_USER, profile.getUsername());
        assertEquals(TEST_PASSWORD, profile.getPassword());
        assertEquals(mServerRootCa, profile.getServerRootCaCert());

        // Verify nothing else is set.
        assertNull(profile.getPresharedKey());
        assertNull(profile.getRsaPrivateKey());
        assertNull(profile.getUserCert());
    }

    @Test
    public void testBuildIkev2VpnProfileDigitalSignature() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        final Ikev2VpnProfile profile =
                buildIkev2VpnProfileDigitalSignature(false /* isRestrictedToTestNetworks */);

        checkBasicIkev2VpnProfile(profile);
        assertEquals(mUserCertKey.cert, profile.getUserCert());
        assertEquals(mUserCertKey.key, profile.getRsaPrivateKey());
        assertEquals(mServerRootCa, profile.getServerRootCaCert());

        // Verify nothing else is set.
        assertNull(profile.getUsername());
        assertNull(profile.getPassword());
        assertNull(profile.getPresharedKey());
    }

    private void verifyProvisionVpnProfile(
            boolean hasActivateVpn, boolean hasActivatePlatformVpn, boolean expectIntent)
            throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        setAppop(AppOpsManager.OP_ACTIVATE_VPN, hasActivateVpn);
        setAppop(AppOpsManager.OP_ACTIVATE_PLATFORM_VPN, hasActivatePlatformVpn);

        final Ikev2VpnProfile profile =
                buildIkev2VpnProfilePsk(false /* isRestrictedToTestNetworks */);
        final Intent intent = sVpnMgr.provisionVpnProfile(profile);
        assertEquals(expectIntent, intent != null);
    }

    @Test
    public void testProvisionVpnProfileNoPreviousConsent() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        verifyProvisionVpnProfile(false /* hasActivateVpn */,
                false /* hasActivatePlatformVpn */, true /* expectIntent */);
    }

    @Test
    public void testProvisionVpnProfilePlatformVpnConsented() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        verifyProvisionVpnProfile(false /* hasActivateVpn */,
                true /* hasActivatePlatformVpn */, false /* expectIntent */);
    }

    @Test
    public void testProvisionVpnProfileVpnServiceConsented() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        verifyProvisionVpnProfile(true /* hasActivateVpn */,
                false /* hasActivatePlatformVpn */, false /* expectIntent */);
    }

    @Test
    public void testProvisionVpnProfileAllPreConsented() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        verifyProvisionVpnProfile(true /* hasActivateVpn */,
                true /* hasActivatePlatformVpn */, false /* expectIntent */);
    }

    @Test
    public void testDeleteVpnProfile() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        setAppop(AppOpsManager.OP_ACTIVATE_PLATFORM_VPN, true);

        final Ikev2VpnProfile profile =
                buildIkev2VpnProfilePsk(false /* isRestrictedToTestNetworks */);
        assertNull(sVpnMgr.provisionVpnProfile(profile));

        // Verify that deleting the profile works (even without the appop)
        setAppop(AppOpsManager.OP_ACTIVATE_PLATFORM_VPN, false);
        sVpnMgr.deleteProvisionedVpnProfile();

        // Test that the profile was deleted - starting it should throw an IAE.
        try {
            setAppop(AppOpsManager.OP_ACTIVATE_PLATFORM_VPN, true);
            sVpnMgr.startProvisionedVpnProfile();
            fail("Expected IllegalArgumentException due to missing profile");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testStartVpnProfileNoPreviousConsent() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        setAppop(AppOpsManager.OP_ACTIVATE_VPN, false);
        setAppop(AppOpsManager.OP_ACTIVATE_PLATFORM_VPN, false);

        // Make sure the VpnProfile is not provisioned already.
        sVpnMgr.stopProvisionedVpnProfile();

        try {
            sVpnMgr.startProvisionedVpnProfile();
            fail("Expected SecurityException for missing consent");
        } catch (SecurityException expected) {
        }
    }

    @Test
    public void testStartStopVpnProfile() throws Exception {
        assumeTrue(mCtsNetUtils.hasIpsecTunnelsFeature());

        // Requires MANAGE_TEST_NETWORKS to provision a test-mode profile.
        runWithShellPermissionIdentity(() -> {
            mCtsNetUtils.setAppopPrivileged(AppOpsManager.OP_ACTIVATE_PLATFORM_VPN, true);

            final Ikev2VpnProfile profile =
                    buildIkev2VpnProfilePsk(true /* isRestrictedToTestNetworks */);
            assertNull(sVpnMgr.provisionVpnProfile(profile));

            sVpnMgr.startProvisionedVpnProfile();
            // TODO: When IKEv2 setup is injectable, verify network was set up properly.

            sVpnMgr.stopProvisionedVpnProfile();
            // TODO: When IKEv2 setup is injectable, verify network is lost.
        }, Manifest.permission.MANAGE_TEST_NETWORKS);
    }

    private static class CertificateAndKey {
        public final X509Certificate cert;
        public final PrivateKey key;

        CertificateAndKey(X509Certificate cert, PrivateKey key) {
            this.cert = cert;
            this.key = key;
        }
    }

    private static CertificateAndKey generateRandomCertAndKeyPair() throws Exception {
        final Date validityBeginDate =
                new Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1L));
        final Date validityEndDate =
                new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(1L));

        // Generate a keypair
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        final X500Principal dnName = new X500Principal("CN=test.android.com");
        final X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setSubjectDN(dnName);
        certGen.setIssuerDN(dnName);
        certGen.setNotBefore(validityBeginDate);
        certGen.setNotAfter(validityEndDate);
        certGen.setPublicKey(keyPair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        final X509Certificate cert = certGen.generate(keyPair.getPrivate(), "AndroidOpenSSL");
        return new CertificateAndKey(cert, keyPair.getPrivate());
    }
}
