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

import static android.net.ipsec.ike.exceptions.IkeProtocolException.ERROR_TYPE_NO_PROPOSAL_CHOSEN;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.net.LinkAddress;
import android.net.ipsec.ike.IkeFqdnIdentification;
import android.net.ipsec.ike.IkeSession;
import android.net.ipsec.ike.IkeSessionParams;
import android.net.ipsec.ike.exceptions.IkeException;
import android.net.ipsec.ike.exceptions.IkeProtocolException;
import android.platform.test.annotations.AppModeFull;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;

@RunWith(AndroidJUnit4.class)
@AppModeFull(reason = "MANAGE_IPSEC_TUNNELS permission can't be granted to instant apps")
public class IkeSessionPskTest extends IkeSessionTestBase {
    // Test vectors for success workflow
    private static final String SUCCESS_IKE_INIT_RESP =
            "46B8ECA1E0D72A18B45427679F9245D421202220000000000000015022000030"
                    + "0000002C010100040300000C0100000C800E0080030000080300000203000008"
                    + "0200000200000008040000022800008800020000A7AA3435D088EC1A2B7C2A47"
                    + "1FA1B85F1066C9B2006E7C353FB5B5FDBC2A88347ED2C6F5B7A265D03AE34039"
                    + "6AAC0145CFCC93F8BDB219DDFF22A603B8856A5DC59B6FAB7F17C5660CF38670"
                    + "8794FC72F273ADEB7A4F316519794AED6F8AB61F95DFB360FAF18C6C8CABE471"
                    + "6E18FE215348C2E582171A57FC41146B16C4AFE429000024A634B61C0E5C90C6"
                    + "8D8818B0955B125A9B1DF47BBD18775710792E651083105C2900001C00004004"
                    + "406FA3C5685A16B9B72C7F2EEE9993462C619ABE2900001C00004005AF905A87"
                    + "0A32222AA284A7070585601208A282F0290000080000402E290000100000402F"
                    + "00020003000400050000000800004014";
    private static final String SUCCESS_IKE_AUTH_RESP =
            "46B8ECA1E0D72A18B45427679F9245D42E20232000000001000000EC240000D0"
                    + "0D06D37198F3F0962DE8170D66F1A9008267F98CDD956D984BDCED2FC7FAF84A"
                    + "A6664EF25049B46B93C9ED420488E0C172AA6635BF4011C49792EF2B88FE7190"
                    + "E8859FEEF51724FD20C46E7B9A9C3DC4708EF7005707A18AB747C903ABCEAC5C"
                    + "6ECF5A5FC13633DCE3844A920ED10EF202F115DBFBB5D6D2D7AB1F34EB08DE7C"
                    + "A54DCE0A3A582753345CA2D05A0EFDB9DC61E81B2483B7D13EEE0A815D37252C"
                    + "23D2F29E9C30658227D2BB0C9E1A481EAA80BC6BE9006BEDC13E925A755A0290"
                    + "AEC4164D29997F52ED7DCC2E";
    private static final String SUCCESS_CREATE_CHILD_RESP =
            "46B8ECA1E0D72A18B45427679F9245D42E20242000000002000000CC210000B0"
                    + "484565D4AF6546274674A8DE339E9C9584EE2326AB9260F41C4D0B6C5B02D1D"
                    + "2E8394E3CDE3094895F2ACCABCDCA8E82960E5196E9622BD13745FC8D6A2BED"
                    + "E561FF5D9975421BC463C959A3CBA3478256B6D278159D99B512DDF56AC1658"
                    + "63C65A986F395FE8B1476124B91F83FD7865304EB95B22CA4DD9601DA7A2533"
                    + "ABF4B36EB1B8CD09522F6A600032316C74E562E6756D9D49D945854E2ABDC4C"
                    + "3AF36305353D60D40B58BE44ABF82";
    private static final String SUCCESS_DELETE_CHILD_RESP =
            "46B8ECA1E0D72A18B45427679F9245D42E202520000000030000004C2A000030"
                    + "0C5CEB882DBCA65CE32F4C53909335F1365C91C555316C5E9D9FB553F7AA916"
                    + "EF3A1D93460B7FABAF0B4B854";
    private static final String SUCCESS_DELETE_IKE_RESP =
            "46B8ECA1E0D72A18B45427679F9245D42E202520000000040000004C00000030"
                    + "9352D71100777B00ABCC6BD7DBEA697827FFAAA48DF9A54D1D68161939F5DC8"
                    + "6743A7CEB2BE34AC00095A5B8";

    private IkeSession openIkeSessionWithRemoteAddress(InetAddress remoteAddress) {
        IkeSessionParams ikeParams =
                new IkeSessionParams.Builder(sContext)
                        .setNetwork(mTunNetwork)
                        .setServerHostname(remoteAddress.getHostAddress())
                        .addSaProposal(SaProposalTest.buildIkeSaProposalWithNormalModeCipher())
                        .addSaProposal(SaProposalTest.buildIkeSaProposalWithCombinedModeCipher())
                        .setLocalIdentification(new IkeFqdnIdentification(LOCAL_HOSTNAME))
                        .setRemoteIdentification(new IkeFqdnIdentification(REMOTE_HOSTNAME))
                        .setAuthPsk(IKE_PSK)
                        .build();
        return new IkeSession(
                sContext,
                ikeParams,
                buildTunnelModeChildSessionParams(),
                mUserCbExecutor,
                mIkeSessionCallback,
                mFirstChildSessionCallback);
    }

    @Test
    public void testIkeSessionSetupAndChildSessionSetupWithTunnelMode() throws Exception {
        if (!hasTunnelsFeature()) return;

        // Open IKE Session
        IkeSession ikeSession = openIkeSessionWithRemoteAddress(mRemoteAddress);
        performSetupIkeAndFirstChildBlocking(SUCCESS_IKE_INIT_RESP, SUCCESS_IKE_AUTH_RESP);

        // IKE INIT and IKE AUTH takes two exchanges. Message ID starts from 2
        int expectedMsgId = 2;

        verifyIkeSessionSetupBlocking();
        verifyChildSessionSetupBlocking(
                mFirstChildSessionCallback,
                Arrays.asList(TUNNEL_MODE_INBOUND_TS),
                Arrays.asList(TUNNEL_MODE_OUTBOUND_TS),
                Arrays.asList(EXPECTED_INTERNAL_LINK_ADDR));

        IpSecTransformCallRecord firstTransformRecordA =
                mFirstChildSessionCallback.awaitNextCreatedIpSecTransform();
        IpSecTransformCallRecord firstTransformRecordB =
                mFirstChildSessionCallback.awaitNextCreatedIpSecTransform();
        verifyCreateIpSecTransformPair(firstTransformRecordA, firstTransformRecordB);

        // Open additional Child Session
        TestChildSessionCallback additionalChildCb = new TestChildSessionCallback();
        ikeSession.openChildSession(buildTunnelModeChildSessionParams(), additionalChildCb);
        mTunUtils.awaitReqAndInjectResp(
                IKE_DETERMINISTIC_INITIATOR_SPI,
                expectedMsgId++,
                true /* expectedUseEncap */,
                SUCCESS_CREATE_CHILD_RESP);

        // Verify opening additional Child Session
        verifyChildSessionSetupBlocking(
                additionalChildCb,
                Arrays.asList(TUNNEL_MODE_INBOUND_TS),
                Arrays.asList(TUNNEL_MODE_OUTBOUND_TS),
                new ArrayList<LinkAddress>());
        IpSecTransformCallRecord additionalTransformRecordA =
                additionalChildCb.awaitNextCreatedIpSecTransform();
        IpSecTransformCallRecord additionalTransformRecordB =
                additionalChildCb.awaitNextCreatedIpSecTransform();
        verifyCreateIpSecTransformPair(additionalTransformRecordA, additionalTransformRecordB);

        // Close additional Child Session
        ikeSession.closeChildSession(additionalChildCb);
        mTunUtils.awaitReqAndInjectResp(
                IKE_DETERMINISTIC_INITIATOR_SPI,
                expectedMsgId++,
                true /* expectedUseEncap */,
                SUCCESS_DELETE_CHILD_RESP);

        verifyDeleteIpSecTransformPair(
                additionalChildCb, additionalTransformRecordA, additionalTransformRecordB);
        additionalChildCb.awaitOnClosed();

        // Close IKE Session
        ikeSession.close();
        performCloseIkeBlocking(expectedMsgId++, SUCCESS_DELETE_IKE_RESP);
        verifyCloseIkeAndChildBlocking(firstTransformRecordA, firstTransformRecordB);
    }

    @Test
    public void testIkeSessionKillWithTunnelMode() throws Exception {
        if (!hasTunnelsFeature()) return;

        // Open IKE Session
        IkeSession ikeSession = openIkeSessionWithRemoteAddress(mRemoteAddress);
        performSetupIkeAndFirstChildBlocking(SUCCESS_IKE_INIT_RESP, SUCCESS_IKE_AUTH_RESP);

        ikeSession.kill();
        mFirstChildSessionCallback.awaitOnClosed();
        mIkeSessionCallback.awaitOnClosed();
    }

    @Test
    public void testIkeInitFail() throws Exception {
        final String ikeInitFailRespHex =
                "46B8ECA1E0D72A180000000000000000292022200000000000000024000000080000000E";

        // Open IKE Session
        IkeSession ikeSession = openIkeSessionWithRemoteAddress(mRemoteAddress);
        int expectedMsgId = 0;
        mTunUtils.awaitReqAndInjectResp(
                IKE_DETERMINISTIC_INITIATOR_SPI,
                expectedMsgId++,
                false /* expectedUseEncap */,
                ikeInitFailRespHex);

        mFirstChildSessionCallback.awaitOnClosed();

        IkeException exception = mIkeSessionCallback.awaitOnClosedException();
        assertNotNull(exception);
        assertTrue(exception instanceof IkeProtocolException);
        IkeProtocolException protocolException = (IkeProtocolException) exception;
        assertEquals(ERROR_TYPE_NO_PROPOSAL_CHOSEN, protocolException.getErrorType());
        assertArrayEquals(EXPECTED_PROTOCOL_ERROR_DATA_NONE, protocolException.getErrorData());
    }

    // TODO(b/155821007): Verify rekey process and handling IKE_AUTH failure

    // TODO(b/155821007): Test creating transport mode Child SA
}
