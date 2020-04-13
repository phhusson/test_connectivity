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
package android.net.cts

import android.app.Instrumentation
import android.content.Context
import android.net.ConnectivityManager
import android.net.KeepalivePacketData
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkAgent
import android.net.NetworkAgent.CMD_ADD_KEEPALIVE_PACKET_FILTER
import android.net.NetworkAgent.CMD_PREVENT_AUTOMATIC_RECONNECT
import android.net.NetworkAgent.CMD_REMOVE_KEEPALIVE_PACKET_FILTER
import android.net.NetworkAgent.CMD_SAVE_ACCEPT_UNVALIDATED
import android.net.NetworkAgent.CMD_START_SOCKET_KEEPALIVE
import android.net.NetworkAgent.CMD_STOP_SOCKET_KEEPALIVE
import android.net.NetworkAgentConfig
import android.net.NetworkCapabilities
import android.net.NetworkProvider
import android.net.NetworkRequest
import android.net.SocketKeepalive
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnAddKeepalivePacketFilter
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnAutomaticReconnectDisabled
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnBandwidthUpdateRequested
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnNetworkUnwanted
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnRemoveKeepalivePacketFilter
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnSaveAcceptUnvalidated
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnStartSocketKeepalive
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnStopSocketKeepalive
import androidx.test.InstrumentationRegistry
import androidx.test.runner.AndroidJUnit4
import com.android.internal.util.AsyncChannel
import com.android.testutils.ArrayTrackRecord
import com.android.testutils.DevSdkIgnoreRule
import com.android.testutils.RecorderCallback.CallbackEntry.Lost
import com.android.testutils.TestableNetworkCallback
import org.junit.After
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// This test doesn't really have a constraint on how fast the methods should return. If it's
// going to fail, it will simply wait forever, so setting a high timeout lowers the flake ratio
// without affecting the run time of successful runs. Thus, set a very high timeout.
private const val DEFAULT_TIMEOUT_MS = 5000L
// Any legal score (0~99) for the test network would do, as it is going to be kept up by the
// requests filed by the test and should never match normal internet requests. 70 is the default
// score of Ethernet networks, it's as good a value as any other.
private const val TEST_NETWORK_SCORE = 70
private const val FAKE_NET_ID = 1098
private val instrumentation: Instrumentation
    get() = InstrumentationRegistry.getInstrumentation()
private val context: Context
    get() = InstrumentationRegistry.getContext()
private fun Message(what: Int, arg1: Int, arg2: Int, obj: Any?) = Message.obtain().also {
    it.what = what
    it.arg1 = arg1
    it.arg2 = arg2
    it.obj = obj
}

@RunWith(AndroidJUnit4::class)
class NetworkAgentTest {
    @Rule @JvmField
    val ignoreRule = DevSdkIgnoreRule(ignoreClassUpTo = Build.VERSION_CODES.Q)

    private val LOCAL_IPV4_ADDRESS = InetAddress.parseNumericAddress("192.0.2.1")
    private val REMOTE_IPV4_ADDRESS = InetAddress.parseNumericAddress("192.0.2.2")

    private val mCM = context.getSystemService(ConnectivityManager::class.java)
    private val mHandlerThread = HandlerThread("${javaClass.simpleName} handler thread")
    private val mFakeConnectivityService by lazy { FakeConnectivityService(mHandlerThread.looper) }

    private class Provider(context: Context, looper: Looper) :
            NetworkProvider(context, looper, "NetworkAgentTest NetworkProvider")

    private val agentsToCleanUp = mutableListOf<NetworkAgent>()
    private val callbacksToCleanUp = mutableListOf<TestableNetworkCallback>()

    @Before
    fun setUp() {
        instrumentation.getUiAutomation().adoptShellPermissionIdentity()
        mHandlerThread.start()
    }

    @After
    fun tearDown() {
        agentsToCleanUp.forEach { it.unregister() }
        callbacksToCleanUp.forEach { mCM.unregisterNetworkCallback(it) }
        mHandlerThread.quitSafely()
        instrumentation.getUiAutomation().dropShellPermissionIdentity()
    }

    /**
     * A fake that helps simulating ConnectivityService talking to a harnessed agent.
     * This fake only supports speaking to one harnessed agent at a time because it
     * only keeps track of one async channel.
     */
    private class FakeConnectivityService(looper: Looper) {
        private val CMD_EXPECT_DISCONNECT = 1
        private var disconnectExpected = false
        private val msgHistory = ArrayTrackRecord<Message>().newReadHead()
        private val asyncChannel = AsyncChannel()
        private val handler = object : Handler(looper) {
            override fun handleMessage(msg: Message) {
                msgHistory.add(Message.obtain(msg)) // make a copy as the original will be recycled
                when (msg.what) {
                    CMD_EXPECT_DISCONNECT -> disconnectExpected = true
                    AsyncChannel.CMD_CHANNEL_HALF_CONNECTED ->
                        asyncChannel.sendMessage(AsyncChannel.CMD_CHANNEL_FULL_CONNECTION)
                    AsyncChannel.CMD_CHANNEL_DISCONNECTED ->
                        if (!disconnectExpected) {
                            fail("Agent unexpectedly disconnected")
                        } else {
                            disconnectExpected = false
                        }
                }
            }
        }

        fun connect(agentMsngr: Messenger) = asyncChannel.connect(context, handler, agentMsngr)

        fun disconnect() = asyncChannel.disconnect()

        fun sendMessage(what: Int, arg1: Int = 0, arg2: Int = 0, obj: Any? = null) =
            asyncChannel.sendMessage(Message(what, arg1, arg2, obj))

        fun expectMessage(what: Int) =
            assertNotNull(msgHistory.poll(DEFAULT_TIMEOUT_MS) { it.what == what })

        fun willExpectDisconnectOnce() = handler.sendEmptyMessage(CMD_EXPECT_DISCONNECT)
    }

    private open class TestableNetworkAgent(
        val looper: Looper,
        nc: NetworkCapabilities,
        lp: LinkProperties,
        conf: NetworkAgentConfig
    ) : NetworkAgent(context, looper, TestableNetworkAgent::class.java.simpleName /* tag */,
            nc, lp, TEST_NETWORK_SCORE, conf, Provider(context, looper)) {
        private val history = ArrayTrackRecord<CallbackEntry>().newReadHead()

        sealed class CallbackEntry {
            object OnBandwidthUpdateRequested : CallbackEntry()
            object OnNetworkUnwanted : CallbackEntry()
            data class OnAddKeepalivePacketFilter(
                val slot: Int,
                val packet: KeepalivePacketData
            ) : CallbackEntry()
            data class OnRemoveKeepalivePacketFilter(val slot: Int) : CallbackEntry()
            data class OnStartSocketKeepalive(
                val slot: Int,
                val interval: Int,
                val packet: KeepalivePacketData
            ) : CallbackEntry()
            data class OnStopSocketKeepalive(val slot: Int) : CallbackEntry()
            data class OnSaveAcceptUnvalidated(val accept: Boolean) : CallbackEntry()
            object OnAutomaticReconnectDisabled : CallbackEntry()
        }

        override fun onBandwidthUpdateRequested() {
            history.add(OnBandwidthUpdateRequested)
        }

        override fun onNetworkUnwanted() {
            history.add(OnNetworkUnwanted)
        }

        override fun onAddKeepalivePacketFilter(slot: Int, packet: KeepalivePacketData) {
            history.add(OnAddKeepalivePacketFilter(slot, packet))
        }

        override fun onRemoveKeepalivePacketFilter(slot: Int) {
            history.add(OnRemoveKeepalivePacketFilter(slot))
        }

        override fun onStartSocketKeepalive(
            slot: Int,
            interval: Duration,
            packet: KeepalivePacketData
        ) {
            history.add(OnStartSocketKeepalive(slot, interval.seconds.toInt(), packet))
        }

        override fun onStopSocketKeepalive(slot: Int) {
            history.add(OnStopSocketKeepalive(slot))
        }

        override fun onSaveAcceptUnvalidated(accept: Boolean) {
            history.add(OnSaveAcceptUnvalidated(accept))
        }

        override fun onAutomaticReconnectDisabled() {
            history.add(OnAutomaticReconnectDisabled)
        }

        inline fun <reified T : CallbackEntry> expectCallback(): T {
            val foundCallback = history.poll(DEFAULT_TIMEOUT_MS)
            assertTrue(foundCallback is T, "Expected ${T::class} but found $foundCallback")
            return foundCallback
        }

        fun assertNoCallback() {
            assertTrue(waitForIdle(DEFAULT_TIMEOUT_MS), "Handler never became idle")
            assertNull(history.peek())
        }
    }

    private fun requestNetwork(request: NetworkRequest, callback: TestableNetworkCallback) {
        mCM.requestNetwork(request, callback)
        callbacksToCleanUp.add(callback)
    }

    private fun createNetworkAgent(): TestableNetworkAgent {
        val nc = NetworkCapabilities().apply {
            addTransportType(NetworkCapabilities.TRANSPORT_TEST)
            removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
            removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)
            addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)
            addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
        val lp = LinkProperties().apply {
            addLinkAddress(LinkAddress(LOCAL_IPV4_ADDRESS, 0))
        }
        val config = NetworkAgentConfig.Builder().build()
        return TestableNetworkAgent(mHandlerThread.looper, nc, lp, config).also {
            agentsToCleanUp.add(it)
        }
    }

    private fun createConnectedNetworkAgent(): Pair<TestableNetworkAgent, TestableNetworkCallback> {
        val request: NetworkRequest = NetworkRequest.Builder()
                .clearCapabilities()
                .addTransportType(NetworkCapabilities.TRANSPORT_TEST)
                .build()
        val callback = TestableNetworkCallback(timeoutMs = DEFAULT_TIMEOUT_MS)
        requestNetwork(request, callback)
        val agent = createNetworkAgent()
        agent.register()
        agent.markConnected()
        return agent to callback
    }

    private fun createNetworkAgentWithFakeCS() = createNetworkAgent().also {
        mFakeConnectivityService.connect(it.registerForTest(Network(FAKE_NET_ID)))
    }

    @Test
    fun testConnectAndUnregister() {
        val (agent, callback) = createConnectedNetworkAgent()
        callback.expectAvailableThenValidatedCallbacks(agent.network)
        agent.unregister()
        callback.expectCallback<Lost>(agent.network)
        agent.expectCallback<OnNetworkUnwanted>()
        assertFailsWith<IllegalStateException>("Must not be able to register an agent twice") {
            agent.register()
        }
    }

    @Test
    fun testOnBandwidthUpdateRequested() {
        val (agent, callback) = createConnectedNetworkAgent()
        callback.expectAvailableThenValidatedCallbacks(agent.network)
        mCM.requestBandwidthUpdate(agent.network)
        agent.expectCallback<OnBandwidthUpdateRequested>()
        agent.unregister()
    }

    @Test
    fun testSocketKeepalive(): Unit = createNetworkAgentWithFakeCS().let { agent ->
        val packet = object : KeepalivePacketData(
                LOCAL_IPV4_ADDRESS /* srcAddress */, 1234 /* srcPort */,
                REMOTE_IPV4_ADDRESS /* dstAddress */, 4567 /* dstPort */,
                ByteArray(100 /* size */) { it.toByte() /* init */ }) {}
        val slot = 4
        val interval = 37

        mFakeConnectivityService.sendMessage(CMD_ADD_KEEPALIVE_PACKET_FILTER,
                arg1 = slot, obj = packet)
        mFakeConnectivityService.sendMessage(CMD_START_SOCKET_KEEPALIVE,
                arg1 = slot, arg2 = interval, obj = packet)

        agent.expectCallback<OnAddKeepalivePacketFilter>().let {
            assertEquals(it.slot, slot)
            assertEquals(it.packet, packet)
        }
        agent.expectCallback<OnStartSocketKeepalive>().let {
            assertEquals(it.slot, slot)
            assertEquals(it.interval, interval)
            assertEquals(it.packet, packet)
        }

        agent.assertNoCallback()

        // Check that when the agent sends a keepalive event, ConnectivityService receives the
        // expected message.
        agent.sendSocketKeepaliveEvent(slot, SocketKeepalive.ERROR_UNSUPPORTED)
        mFakeConnectivityService.expectMessage(NetworkAgent.EVENT_SOCKET_KEEPALIVE).let() {
            assertEquals(slot, it.arg1)
            assertEquals(SocketKeepalive.ERROR_UNSUPPORTED, it.arg2)
        }

        mFakeConnectivityService.sendMessage(CMD_STOP_SOCKET_KEEPALIVE, arg1 = slot)
        mFakeConnectivityService.sendMessage(CMD_REMOVE_KEEPALIVE_PACKET_FILTER, arg1 = slot)
        agent.expectCallback<OnStopSocketKeepalive>().let {
            assertEquals(it.slot, slot)
        }
        agent.expectCallback<OnRemoveKeepalivePacketFilter>().let {
            assertEquals(it.slot, slot)
        }
    }

    @Test
    fun testSetAcceptUnvalidated() {
        createNetworkAgentWithFakeCS().let { agent ->
            mFakeConnectivityService.sendMessage(CMD_SAVE_ACCEPT_UNVALIDATED, 1)
            agent.expectCallback<OnSaveAcceptUnvalidated>().let {
                assertTrue(it.accept)
            }
            agent.assertNoCallback()
        }
        createNetworkAgentWithFakeCS().let { agent ->
            mFakeConnectivityService.sendMessage(CMD_SAVE_ACCEPT_UNVALIDATED, 0)
            mFakeConnectivityService.sendMessage(CMD_PREVENT_AUTOMATIC_RECONNECT)
            agent.expectCallback<OnSaveAcceptUnvalidated>().let {
                assertFalse(it.accept)
            }
            agent.expectCallback<OnAutomaticReconnectDisabled>()
            agent.assertNoCallback()
            // When automatic reconnect is turned off, the network is torn down and
            // ConnectivityService sends a disconnect. This in turn causes the agent
            // to send a DISCONNECTED message to CS.
            mFakeConnectivityService.willExpectDisconnectOnce()
            mFakeConnectivityService.disconnect()
            mFakeConnectivityService.expectMessage(AsyncChannel.CMD_CHANNEL_DISCONNECTED)
            agent.expectCallback<OnNetworkUnwanted>()
        }
        createNetworkAgentWithFakeCS().let { agent ->
            mFakeConnectivityService.sendMessage(CMD_PREVENT_AUTOMATIC_RECONNECT)
            agent.expectCallback<OnAutomaticReconnectDisabled>()
            agent.assertNoCallback()
            mFakeConnectivityService.willExpectDisconnectOnce()
            mFakeConnectivityService.disconnect()
            mFakeConnectivityService.expectMessage(AsyncChannel.CMD_CHANNEL_DISCONNECTED)
            agent.expectCallback<OnNetworkUnwanted>()
        }
    }
}
