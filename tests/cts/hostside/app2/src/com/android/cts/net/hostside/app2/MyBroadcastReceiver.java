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

import static com.android.cts.net.hostside.app2.Common.MANIFEST_RECEIVER;
import static com.android.cts.net.hostside.app2.Common.TAG;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;

/**
 * Receiver that stores received broadcasts in a shared preference.
 */
public class MyBroadcastReceiver extends BroadcastReceiver {

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
        final SharedPreferences prefs = context.getSharedPreferences(mName, Context.MODE_PRIVATE);
        final String pref = intent.getAction();
        final int value = prefs.getInt(pref, 0) + 1;
        Log.d(TAG, "Setting " + pref + " = " + value);
        prefs.edit().putInt(pref, value).apply();
    }
}
