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

#include "bpf_helpers.h"
#include "bpf_net_helpers.h"
#include "netdbpf/bpf_shared.h"

// Used only by TetheringPrivilegedTests, not by production code.
DEFINE_BPF_MAP_GRW(tether_ingress_map, HASH, TetherIngressKey, TetherIngressValue, 16,
                   AID_NETWORK_STACK)

LICENSE("Apache 2.0");
