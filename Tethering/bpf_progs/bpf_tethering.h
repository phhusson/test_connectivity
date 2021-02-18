/*
 * Copyright (C) 2021 The Android Open Source Project
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

#pragma once

// Common definitions for BPF code in the tethering mainline module.
// These definitions are available to:
// - The BPF programs in Tethering/bpf_progs/
// - JNI code that depends on the bpf_tethering_headers library.

#define BPF_TETHER_ERRORS    \
    ERR(INVALID_IP_VERSION)  \
    ERR(LOW_TTL)             \
    ERR(INVALID_TCP_HEADER)  \
    ERR(TCP_CONTROL_PACKET)  \
    ERR(NON_GLOBAL_SRC)      \
    ERR(NON_GLOBAL_DST)      \
    ERR(LOCAL_SRC_DST)       \
    ERR(NO_STATS_ENTRY)      \
    ERR(NO_LIMIT_ENTRY)      \
    ERR(BELOW_IPV4_MTU)      \
    ERR(BELOW_IPV6_MTU)      \
    ERR(LIMIT_REACHED)       \
    ERR(CHANGE_HEAD_FAILED)  \
    ERR(TOO_SHORT)           \
    ERR(HAS_IP_OPTIONS)      \
    ERR(IS_IP_FRAG)          \
    ERR(CHECKSUM)            \
    ERR(NON_TCP_UDP)         \
    ERR(NON_TCP)             \
    ERR(SHORT_L4_HEADER)     \
    ERR(SHORT_TCP_HEADER)    \
    ERR(SHORT_UDP_HEADER)    \
    ERR(UDP_CSUM_ZERO)       \
    ERR(TRUNCATED_IPV4)      \
    ERR(_MAX)

#define ERR(x) BPF_TETHER_ERR_ ##x,
enum {
    BPF_TETHER_ERRORS
};
#undef ERR

#define ERR(x) #x,
static const char *bpf_tether_errors[] = {
    BPF_TETHER_ERRORS
};
#undef ERR
