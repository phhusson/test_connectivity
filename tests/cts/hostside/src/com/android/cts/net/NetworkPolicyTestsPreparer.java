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
package com.android.cts.net;

import com.android.tradefed.device.DeviceNotAvailableException;
import com.android.tradefed.device.ITestDevice;
import com.android.tradefed.invoker.TestInformation;
import com.android.tradefed.log.LogUtil;
import com.android.tradefed.targetprep.ITargetPreparer;

public class NetworkPolicyTestsPreparer implements ITargetPreparer {
    private ITestDevice mDevice;
    private String mOriginalAppStandbyEnabled;

    @Override
    public void setUp(TestInformation testInformation) throws DeviceNotAvailableException {
        mDevice = testInformation.getDevice();
        mOriginalAppStandbyEnabled = getAppStandbyEnabled();
        setAppStandbyEnabled("1");
        LogUtil.CLog.d("Original app_standby_enabled: " + mOriginalAppStandbyEnabled);
    }

    @Override
    public void tearDown(TestInformation testInformation, Throwable e)
            throws DeviceNotAvailableException {
        setAppStandbyEnabled(mOriginalAppStandbyEnabled);
    }

    private void setAppStandbyEnabled(String appStandbyEnabled) throws DeviceNotAvailableException {
        if ("null".equals(appStandbyEnabled)) {
            executeCmd("settings delete global app_standby_enabled");
        } else {
            executeCmd("settings put global app_standby_enabled " + appStandbyEnabled);
        }
    }

    private String getAppStandbyEnabled() throws DeviceNotAvailableException {
        return executeCmd("settings get global app_standby_enabled").trim();
    }

    private String executeCmd(String cmd) throws DeviceNotAvailableException {
        final String output = mDevice.executeShellCommand(cmd).trim();
        LogUtil.CLog.d("Output for '%s': %s", cmd, output);
        return output;
    }
}
