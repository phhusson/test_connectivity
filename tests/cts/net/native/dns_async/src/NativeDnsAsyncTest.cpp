/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h> /* poll */
#include <resolv.h>
#include <string.h>

#include <android/multinetwork.h>
#include <gtest/gtest.h>

namespace {
constexpr int MAXPACKET = 8 * 1024;
constexpr int PTON_MAX = 16;

int getAsyncResponse(int fd, int timeoutMs, int* rcode, u_char* buf, int bufLen) {
    struct pollfd wait_fd[1];
    wait_fd[0].fd = fd;
    wait_fd[0].events = POLLIN;
    short revents;
    int ret;
    ret = poll(wait_fd, 1, timeoutMs);
    revents = wait_fd[0].revents;
    if (revents & POLLIN) {
        int n = android_res_nresult(fd, rcode, buf, bufLen);
        return n;
    }

    return -1;
}

std::vector<std::string> extractIpAddressAnswers(u_char* buf, int bufLen, int ipType) {
    ns_msg handle;
    if (ns_initparse((const uint8_t*) buf, bufLen, &handle) < 0) {
        return {};
    }
    int ancount = ns_msg_count(handle, ns_s_an);
    ns_rr rr;
    std::vector<std::string> answers;
    for (int i = 0; i < ancount; i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            continue;
        }
        const u_char* rdata = ns_rr_rdata(rr);
        char buffer[INET6_ADDRSTRLEN];
        if (inet_ntop(ipType, (const char*) rdata, buffer, sizeof(buffer))) {
            answers.push_back(buffer);
        }
    }
    return answers;
}

void expectAnswersValid(int fd, int ipType, int expectedRcode) {
    int rcode = -1;
    u_char buf[MAXPACKET] = {};
    int res = getAsyncResponse(fd, 10000, &rcode, buf, MAXPACKET);
    EXPECT_GT(res, 0);
    EXPECT_EQ(rcode, expectedRcode);


    if (expectedRcode == NOERROR) {
        auto answers = extractIpAddressAnswers(buf, res, ipType);
        EXPECT_GT(answers.size(), 0U);
        for (auto &answer : answers) {
            char pton[PTON_MAX];
            EXPECT_EQ(1, inet_pton(ipType, answer.c_str(), pton));
        }
    }
}

} // namespace

TEST (NativeDnsAsyncTest, Async_Query) {
    // V4
    int fd = android_res_nquery(NETWORK_UNSPECIFIED ,"www.google.com", ns_c_in, ns_t_a);
    EXPECT_GT(fd, 0);
    expectAnswersValid(fd, AF_INET, NOERROR);

    // V6
    fd = android_res_nquery(NETWORK_UNSPECIFIED ,"www.google.com", ns_c_in, ns_t_aaaa);
    EXPECT_GT(fd, 0);
    expectAnswersValid(fd, AF_INET6, NOERROR);
}

TEST (NativeDnsAsyncTest, Async_Send) {
    // V4
    u_char buf[MAXPACKET] = {};
    int len = res_mkquery(QUERY, "www.youtube.com",
            ns_c_in, ns_t_a, nullptr, 0, nullptr, buf, sizeof(buf));
    EXPECT_GT(len, 0);
    int fd = android_res_nsend(NETWORK_UNSPECIFIED , buf, len);
    EXPECT_GT(fd, 0);
    expectAnswersValid(fd, AF_INET, NOERROR);

    // V6
    memset(buf, 0, MAXPACKET);
    len = res_mkquery(QUERY, "www.youtube.com",
            ns_c_in, ns_t_aaaa, nullptr, 0, nullptr, buf, sizeof(buf));
    EXPECT_GT(len, 0);
    fd = android_res_nsend(NETWORK_UNSPECIFIED , buf, len);
    EXPECT_GT(fd, 0);
    expectAnswersValid(fd, AF_INET6, NOERROR);
}

TEST (NativeDnsAsyncTest, Async_NXDOMAIN) {
    u_char buf[MAXPACKET] = {};
    int len = res_mkquery(QUERY, "test-nx.metric.gstatic.com",
            ns_c_in, ns_t_a, nullptr, 0, nullptr, buf, sizeof(buf));
    EXPECT_GT(len, 0);
    int fd = android_res_nsend(NETWORK_UNSPECIFIED , buf, len);
    EXPECT_GT(fd, 0);
    expectAnswersValid(fd, AF_INET, NXDOMAIN);
}

TEST (NativeDnsAsyncTest, Async_Cancel) {
    int fd = android_res_nquery(NETWORK_UNSPECIFIED ,"www.google.com", ns_c_in, ns_t_a);
    int rcode = -1;
    u_char buf[MAXPACKET] = {};
    android_res_cancel(fd);

    int res = android_res_nresult(fd, &rcode, buf, MAXPACKET);
    EXPECT_EQ(res, -EBADF);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
