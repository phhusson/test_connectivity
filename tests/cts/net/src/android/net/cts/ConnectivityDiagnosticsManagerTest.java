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

import static android.net.ConnectivityDiagnosticsManager.ConnectivityDiagnosticsCallback;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import android.content.Context;
import android.net.ConnectivityDiagnosticsManager;
import android.net.NetworkRequest;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.Executor;

@RunWith(AndroidJUnit4.class)
public class ConnectivityDiagnosticsManagerTest {
    private static final Executor INLINE_EXECUTOR = x -> x.run();
    private static final NetworkRequest DEFAULT_REQUEST = new NetworkRequest.Builder().build();

    private Context mContext;
    private ConnectivityDiagnosticsManager mCdm;
    private ConnectivityDiagnosticsCallback mCallback;

    @Before
    public void setUp() throws Exception {
        mContext = InstrumentationRegistry.getContext();
        mCdm = mContext.getSystemService(ConnectivityDiagnosticsManager.class);

        mCallback = new ConnectivityDiagnosticsCallback() {};
    }

    @Test
    public void testRegisterConnectivityDiagnosticsCallback() {
        mCdm.registerConnectivityDiagnosticsCallback(DEFAULT_REQUEST, INLINE_EXECUTOR, mCallback);
    }

    @Test
    public void testRegisterDuplicateConnectivityDiagnosticsCallback() {
        mCdm.registerConnectivityDiagnosticsCallback(DEFAULT_REQUEST, INLINE_EXECUTOR, mCallback);

        try {
            mCdm.registerConnectivityDiagnosticsCallback(
                    DEFAULT_REQUEST, INLINE_EXECUTOR, mCallback);
            fail("Registering the same callback twice should throw an IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testUnregisterConnectivityDiagnosticsCallback() {
        mCdm.registerConnectivityDiagnosticsCallback(DEFAULT_REQUEST, INLINE_EXECUTOR, mCallback);
        mCdm.unregisterConnectivityDiagnosticsCallback(mCallback);
    }

    @Test
    public void testUnregisterUnknownConnectivityDiagnosticsCallback() {
        // Expected to silently ignore the unregister() call
        mCdm.unregisterConnectivityDiagnosticsCallback(mCallback);
    }
}
