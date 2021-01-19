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

package com.android.networkstack.tethering;

import android.net.MacAddress;

import androidx.annotation.NonNull;

import com.android.net.module.util.Struct;
import com.android.net.module.util.Struct.Field;
import com.android.net.module.util.Struct.Type;

import java.util.Objects;

/** The value of BpfMap which is used for bpf offload. */
public class TetherDownstream6Value extends Struct {
    @Field(order = 0, type = Type.U32)
    public final long oif; // The output interface index.

    // The ethhdr struct which is defined in uapi/linux/if_ether.h
    @Field(order = 1, type = Type.EUI48)
    public final MacAddress ethDstMac; // The destination mac address.
    @Field(order = 2, type = Type.EUI48)
    public final MacAddress ethSrcMac; // The source mac address.
    @Field(order = 3, type = Type.UBE16)
    public final int ethProto; // Packet type ID field.

    @Field(order = 4, type = Type.U16)
    public final int pmtu; // The maximum L3 output path/route mtu.

    public TetherDownstream6Value(final long oif, @NonNull final MacAddress ethDstMac,
            @NonNull final MacAddress ethSrcMac, final int ethProto, final int pmtu) {
        Objects.requireNonNull(ethSrcMac);
        Objects.requireNonNull(ethDstMac);

        this.oif = oif;
        this.ethDstMac = ethDstMac;
        this.ethSrcMac = ethSrcMac;
        this.ethProto = ethProto;
        this.pmtu = pmtu;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;

        if (!(obj instanceof TetherDownstream6Value)) return false;

        final TetherDownstream6Value that = (TetherDownstream6Value) obj;

        return oif == that.oif && ethDstMac.equals(that.ethDstMac)
                && ethSrcMac.equals(that.ethSrcMac) && ethProto == that.ethProto
                && pmtu == that.pmtu;
    }

    @Override
    public int hashCode() {
        return Objects.hash(oif, ethDstMac, ethSrcMac, ethProto, pmtu);
    }

    @Override
    public String toString() {
        return String.format("oif: %d, dstMac: %s, srcMac: %s, proto: %d, pmtu: %d", oif,
                ethDstMac, ethSrcMac, ethProto, pmtu);
    }
}
