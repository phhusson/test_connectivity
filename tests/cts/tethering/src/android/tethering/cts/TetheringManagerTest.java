/*
 * Copyright (C) 2019 The Android Open Source Project
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
package android.tethering.test;

import static org.junit.Assert.fail;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.os.ConditionVariable;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

@RunWith(AndroidJUnit4.class)
public class TetheringManagerTest {

    private Context mContext;

    private ConnectivityManager mCM;

    private TetherChangeReceiver mTetherChangeReceiver;

    private String[] mTetheredList;

    private static final int DEFAULT_TIMEOUT_MS = 60_000;

    @Before
    public void setUp() throws Exception {
        InstrumentationRegistry.getInstrumentation()
                .getUiAutomation()
                .adoptShellPermissionIdentity();
        mContext = InstrumentationRegistry.getContext();
        mCM = (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        mTetherChangeReceiver = new TetherChangeReceiver();
        final IntentFilter filter = new IntentFilter(
                ConnectivityManager.ACTION_TETHER_STATE_CHANGED);
        final Intent intent = mContext.registerReceiver(mTetherChangeReceiver, filter);
        if (intent != null) mTetherChangeReceiver.onReceive(null, intent);
    }

    @After
    public void tearDown() throws Exception {
        mContext.unregisterReceiver(mTetherChangeReceiver);
        InstrumentationRegistry.getInstrumentation()
                .getUiAutomation()
                .dropShellPermissionIdentity();
    }

    private class TetherChangeReceiver extends BroadcastReceiver {
        private class TetherState {
            final ArrayList<String> mAvailable;
            final ArrayList<String> mActive;
            final ArrayList<String> mErrored;

            TetherState(Intent intent) {
                mAvailable = intent.getStringArrayListExtra(
                        ConnectivityManager.EXTRA_AVAILABLE_TETHER);
                mActive = intent.getStringArrayListExtra(
                        ConnectivityManager.EXTRA_ACTIVE_TETHER);
                mErrored = intent.getStringArrayListExtra(
                        ConnectivityManager.EXTRA_ERRORED_TETHER);
            }
        }

        @Override
        public void onReceive(Context content, Intent intent) {
            String action = intent.getAction();
            if (action.equals(ConnectivityManager.ACTION_TETHER_STATE_CHANGED)) {
                mResult.add(new TetherState(intent));
            }
        }

        public final LinkedBlockingQueue<TetherState> mResult = new LinkedBlockingQueue<>();

        // This method expects either an event where one of the interfaces is active, or an event
        // where one of the interface is available followed by one where one of the interfaces is
        // active.
        public void expectActiveTethering(String[] ifaceRegexs) {
            TetherState state = pollAndAssertNoError(DEFAULT_TIMEOUT_MS);
            if (state == null) fail("Do not receive tethering state change broadcast");

            if (isIfaceActive(ifaceRegexs, state)) return;

            if (isIfaceAvailable(ifaceRegexs, state)) {
                state = pollAndAssertNoError(DEFAULT_TIMEOUT_MS);
                if (isIfaceActive(ifaceRegexs, state)) return;
            }

            fail("Tethering is not actived, available ifaces: " + state.mAvailable.toString()
                    + ", active ifaces: " + state.mActive.toString());
        }

        private TetherState pollAndAssertNoError(final int timeout) {
            final TetherState state = pollTetherState(timeout);
            assertNoErroredIfaces(state);
            return state;
        }

        private TetherState pollTetherState(final int timeout) {
            try {
                return mResult.poll(timeout, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                fail("No result after " + timeout + " ms");
                return null;
            }
        }

        private boolean isIfaceActive(final String[] ifaceRegexs, final TetherState state) {
            return isIfaceMatch(ifaceRegexs, state.mActive);
        }

        private boolean isIfaceAvailable(final String[] ifaceRegexs, final TetherState state) {
            return isIfaceMatch(ifaceRegexs, state.mAvailable);
        }

        // This method requires a broadcast to have been recorded iff the timeout is non-zero.
        public void expectNoActiveTethering(final int timeout) {
            final TetherState state = pollAndAssertNoError(timeout);

            if (state == null) {
                if (timeout != 0) {
                    fail("Do not receive tethering state change broadcast");
                }
                return;
            }

            assertNoActiveIfaces(state);

            for (final TetherState ts : mResult) {
                assertNoErroredIfaces(ts);

                assertNoActiveIfaces(ts);
            }
        }

        private void assertNoErroredIfaces(final TetherState state) {
            if (state == null || state.mErrored == null) return;

            if (state.mErrored.size() > 0) {
                fail("Found failed tethering interfaces: " + Arrays.toString(state.mErrored.toArray()));
            }
        }

        private void assertNoActiveIfaces(final TetherState state) {
            if (state.mActive != null && state.mActive.size() > 0) {
                fail("Found active tethering interface: " + Arrays.toString(state.mActive.toArray()));
            }
        }
    }

    private class OnStartTetheringCallback extends
            ConnectivityManager.OnStartTetheringCallback {
        @Override
        public void onTetheringStarted() {
            // Do nothing, TetherChangeReceiver will wait until it receives the broadcast.
        }

        @Override
        public void onTetheringFailed() {
            fail("startTethering fail");
        }
    }

    private static boolean isIfaceMatch(final String[] ifaceRegexs,
            final ArrayList<String> ifaces) {
        if (ifaceRegexs == null) fail("ifaceRegexs should not be null");

        if (ifaces == null) return false;

        for (String s : ifaces) {
            for (String regex : ifaceRegexs) {
                if (s.matches(regex)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Test
    public void testStartTetheringWithStateChangeBroadcast() throws Exception {
        if (!mCM.isTetheringSupported()) return;

        final String[] wifiRegexs = mCM.getTetherableWifiRegexs();
        if (wifiRegexs.length == 0) return;

        mTetherChangeReceiver.expectNoActiveTethering(0 /** timeout */);

        final OnStartTetheringCallback startTetheringCallback = new OnStartTetheringCallback();
        mCM.startTethering(ConnectivityManager.TETHERING_WIFI, true, startTetheringCallback);
        mTetherChangeReceiver.expectActiveTethering(wifiRegexs);

        mCM.stopTethering(ConnectivityManager.TETHERING_WIFI);
        mTetherChangeReceiver.expectNoActiveTethering(DEFAULT_TIMEOUT_MS);
    }
}
