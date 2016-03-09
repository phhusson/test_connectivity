/*
 * Copyright (C) 2016 The Android Open Source Project
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

package com.android.cts.net.hostside.app2;

import static android.net.ConnectivityManager.ACTION_RESTRICT_BACKGROUND_CHANGED;
import static com.android.cts.net.hostside.app2.Common.ACTION_CHECK_NETWORK;
import static com.android.cts.net.hostside.app2.Common.ACTION_GET_COUNTERS;
import static com.android.cts.net.hostside.app2.Common.ACTION_RECEIVER_READY;
import static com.android.cts.net.hostside.app2.Common.EXTRA_ACTION;
import static com.android.cts.net.hostside.app2.Common.EXTRA_RECEIVER_NAME;
import static com.android.cts.net.hostside.app2.Common.MANIFEST_RECEIVER;
import static com.android.cts.net.hostside.app2.Common.RESULT_SEPARATOR;
import static com.android.cts.net.hostside.app2.Common.STATUS_NETWORK_AVAILABLE_PREFIX;
import static com.android.cts.net.hostside.app2.Common.STATUS_NETWORK_UNAVAILABLE_PREFIX;
import static com.android.cts.net.hostside.app2.Common.TAG;
import static com.android.cts.net.hostside.app2.Common.getUid;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;

/**
 * Receiver used to:
 * <ol>
 * <li>Stored received RESTRICT_BACKGROUND_CHANGED broadcasts in a shared preference.
 * <li>Returned the number of RESTRICT_BACKGROUND_CHANGED broadcasts in an ordered broadcast.
 * </ol>
 */
public class MyBroadcastReceiver extends BroadcastReceiver {

    private static final int NETWORK_TIMEOUT_MS = 15 * 1000;

    private final String mName;

    public MyBroadcastReceiver() {
        this(MANIFEST_RECEIVER);
    }

    MyBroadcastReceiver(String name) {
        Log.d(TAG, "Constructing MyBroadcastReceiver named " + name);
        mName = name;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(TAG, "onReceive() for " + mName + ": " + intent);
        final String action = intent.getAction();
        switch (action) {
            case ACTION_RESTRICT_BACKGROUND_CHANGED:
                increaseCounter(context, action);
                break;
            case ACTION_GET_COUNTERS:
                setResultDataFromCounter(context, intent);
                break;
            case ACTION_CHECK_NETWORK:
                checkNetwork(context, intent);
                break;
            case ACTION_RECEIVER_READY:
                final String message = mName + " is ready to rumble";
                Log.d(TAG, message);
                setResultData(message);
                break;
            default:
                Log.e(TAG, "received unexpected action: " + action);
        }
    }

    private void increaseCounter(Context context, String action) {
        final SharedPreferences prefs = context.getSharedPreferences(mName, Context.MODE_PRIVATE);
        final int value = prefs.getInt(action, 0) + 1;
        Log.d(TAG, "increaseCounter('" + action + "'): setting '" + mName + "' to " + value);
        prefs.edit().putInt(action, value).apply();
    }

    private int getCounter(Context context, String action, String receiverName) {
        final SharedPreferences prefs = context.getSharedPreferences(receiverName,
                Context.MODE_PRIVATE);
        final int value = prefs.getInt(action, 0);
        Log.d(TAG, "getCounter('" + action + "', '" + receiverName + "'): " + value);
        return value;
    }

    private void checkNetwork(final Context context, Intent intent) {
        final ConnectivityManager cm = (ConnectivityManager) context
                .getSystemService(Context.CONNECTIVITY_SERVICE);

        final StringBuilder data = new StringBuilder();
        final int apiStatus = cm.getRestrictBackgroundStatus();
        String netStatus;
        try {
            netStatus = checkNetworkStatus(context, cm);
        } catch (InterruptedException e) {
            Log.e(TAG, "Timeout checking network status");
            setResultData(null);
            return;
        }
        data.append(apiStatus).append(RESULT_SEPARATOR);
        if (netStatus != null) {
            data.append(netStatus);
        }
        Log.d(TAG, "checkNetwork: returning " + data);
        setResultData(data.toString());
    }

    private String checkNetworkStatus(final Context context, final ConnectivityManager cm)
            throws InterruptedException {
        final LinkedBlockingQueue<String> result = new LinkedBlockingQueue<>(1);
        new Thread(new Runnable() {

            @Override
            public void run() {
                // TODO: connect to a hostside server instead
                final String address = "http://example.com";
                final NetworkInfo networkInfo = cm.getActiveNetworkInfo();
                Log.d(TAG, "Running checkNetworkStatus() on thread "
                        + Thread.currentThread().getName() + " for UID " + getUid(context)
                        + "\n\tactiveNetworkInfo: " + networkInfo + "\n\tURL: " + address);
                String prefix = STATUS_NETWORK_AVAILABLE_PREFIX;
                try {
                    final URL url = new URL(address);
                    final HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setReadTimeout(NETWORK_TIMEOUT_MS);
                    conn.setConnectTimeout(NETWORK_TIMEOUT_MS);
                    conn.setRequestMethod("GET");
                    conn.setDoInput(true);
                    conn.connect();
                    final int response = conn.getResponseCode();
                    Log.d(TAG, "HTTP response for " + address + ": " + response);
                } catch (Exception e) {
                    Log.d(TAG, "Exception getting " + address + ": " + e);
                    prefix = STATUS_NETWORK_UNAVAILABLE_PREFIX + "Exception " + e + ":";
                }
                final String netInfo = prefix + networkInfo;
                Log.d(TAG, "Offering " + netInfo);
                result.offer(netInfo);
            }
        }, mName).start();
        return result.poll(NETWORK_TIMEOUT_MS * 2, TimeUnit.MILLISECONDS);
    }

    private void setResultDataFromCounter(Context context, Intent intent) {
        final String action = intent.getStringExtra(EXTRA_ACTION);
        if (action == null) {
            Log.e(TAG, "Missing extra '" + EXTRA_ACTION + "' on " + intent);
            return;
        }
        final String receiverName = intent.getStringExtra(EXTRA_RECEIVER_NAME);
        if (receiverName == null) {
            Log.e(TAG, "Missing extra '" + EXTRA_RECEIVER_NAME + "' on " + intent);
            return;
        }
        final int counter = getCounter(context, action, receiverName);
        setResultData(String.valueOf(counter));
    }
}
