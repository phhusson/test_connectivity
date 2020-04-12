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
import android.net.LinkProperties
import android.net.NetworkAgent
import android.net.NetworkAgentConfig
import android.net.NetworkCapabilities
import android.net.NetworkProvider
import android.net.NetworkRequest
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnBandwidthUpdateRequested
import android.net.cts.NetworkAgentTest.TestableNetworkAgent.CallbackEntry.OnNetworkUnwanted
import android.os.Build
import android.os.HandlerThread
import android.os.Looper
import androidx.test.InstrumentationRegistry
import androidx.test.runner.AndroidJUnit4
import com.android.testutils.ArrayTrackRecord
import com.android.testutils.DevSdkIgnoreRule
import com.android.testutils.RecorderCallback.CallbackEntry.Lost
import com.android.testutils.TestableNetworkCallback
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

// This test doesn't really have a constraint on how fast the methods should return. If it's
// going to fail, it will simply wait forever, so setting a high timeout lowers the flake ratio
// without affecting the run time of successful runs. Thus, set a very high timeout.
private const val DEFAULT_TIMEOUT_MS = 5000L
// Any legal score (0~99) for the test network would do, as it is going to be kept up by the
// requests filed by the test and should never match normal internet requests. 70 is the default
// score of Ethernet networks, it's as good a value as any other.
private const val TEST_NETWORK_SCORE = 70
private val instrumentation: Instrumentation
    get() = InstrumentationRegistry.getInstrumentation()
private val context: Context
    get() = InstrumentationRegistry.getContext()

@RunWith(AndroidJUnit4::class)
class NetworkAgentTest {
    @Rule @JvmField
    val ignoreRule = DevSdkIgnoreRule(ignoreClassUpTo = Build.VERSION_CODES.Q)

    private val mCM = context.getSystemService(ConnectivityManager::class.java)
    private val mHandlerThread = HandlerThread("${javaClass.simpleName} handler thread")

    private class Provider(context: Context, looper: Looper) :
            NetworkProvider(context, looper, "NetworkAgentTest NetworkProvider")

    @Before
    fun setUp() {
        instrumentation.getUiAutomation().adoptShellPermissionIdentity()
        mHandlerThread.start()
    }

    @After
    fun tearDown() {
        mHandlerThread.quitSafely()
        instrumentation.getUiAutomation().dropShellPermissionIdentity()
    }

    internal class TestableNetworkAgent(
        looper: Looper,
        nc: NetworkCapabilities,
        lp: LinkProperties,
        conf: NetworkAgentConfig
    ) : NetworkAgent(context, looper, TestableNetworkAgent::class.java.simpleName /* tag */,
            nc, lp, TEST_NETWORK_SCORE, conf, Provider(context, looper)) {
        private val history = ArrayTrackRecord<CallbackEntry>().newReadHead()

        sealed class CallbackEntry {
            object OnBandwidthUpdateRequested : CallbackEntry()
            object OnNetworkUnwanted : CallbackEntry()
        }

        override fun onBandwidthUpdateRequested() {
            super.onBandwidthUpdateRequested()
            history.add(OnBandwidthUpdateRequested)
        }

        override fun onNetworkUnwanted() {
            super.onNetworkUnwanted()
            history.add(OnNetworkUnwanted)
        }

        inline fun <reified T : CallbackEntry> expectCallback() {
            val foundCallback = history.poll(DEFAULT_TIMEOUT_MS)
            assertTrue(foundCallback is T, "Expected ${T::class} but found $foundCallback")
        }
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
        val lp = LinkProperties()
        val config = NetworkAgentConfig.Builder().build()
        return TestableNetworkAgent(mHandlerThread.looper, nc, lp, config)
    }

    private fun createConnectedNetworkAgent(): Pair<TestableNetworkAgent, TestableNetworkCallback> {
        val request: NetworkRequest = NetworkRequest.Builder()
                .clearCapabilities()
                .addTransportType(NetworkCapabilities.TRANSPORT_TEST)
                .build()
        val callback = TestableNetworkCallback(timeoutMs = DEFAULT_TIMEOUT_MS)
        mCM.requestNetwork(request, callback)
        val agent = createNetworkAgent().also { it.register() }
        agent.markConnected()
        return agent to callback
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
}
