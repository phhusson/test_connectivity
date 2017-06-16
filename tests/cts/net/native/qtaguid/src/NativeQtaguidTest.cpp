/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>

#include <gtest/gtest.h>
#include <cutils/qtaguid.h>

int getCtrlRefCnt(int tag, uid_t uid) {
    FILE *fp;
    fp = fopen("/proc/net/xt_qtaguid/ctrl", "r");
    if (!fp)
        return -ENOENT;
    uint64_t full_tag = (uint64_t)tag << 32 | uid;
    char pattern[40];
    snprintf(pattern, sizeof(pattern), " tag=0x%" PRIx64 " (uid=%" PRIu32 ")", full_tag, uid);

    size_t len;
    char *line_buffer = NULL;
    while(getline(&line_buffer, &len, fp) != -1) {
        if (strstr(line_buffer, pattern) == NULL)
            continue;
        int res;
        uint32_t ref_cnt;
        pid_t dummy_pid;
        uint64_t dummy_sk;
        uint64_t k_tag;
        uint32_t k_uid;
        const int TOTAL_PARAM = 5;
        res = sscanf(line_buffer, "sock=%" PRIx64 " tag=0x%" PRIx64 " (uid=%" PRIu32 ") "
                     "pid=%u f_count=%u", &dummy_sk, &k_tag, &k_uid,
                     &dummy_pid, &ref_cnt);
        if (!(res == TOTAL_PARAM && k_tag == full_tag && k_uid == uid))
            res = -EINVAL;
        res = ref_cnt;
        free(line_buffer);
        return res;
    }
    free(line_buffer);
    return -ENOENT;
}

TEST (NativeSocketRefCnt, close_socket_without_untag) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    uid_t uid = getuid();
    int tag = arc4random();
    EXPECT_EQ(0, qtaguid_tagSocket(sockfd, tag, uid));
    EXPECT_GE(2, getCtrlRefCnt(tag, uid));
    close(sockfd);
    EXPECT_EQ(-ENOENT, getCtrlRefCnt(tag, uid));
}

TEST (NativeSocketRefCnt, close_socket_without_untag_ipv6) {
    int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    uid_t uid = getuid();
    int tag = arc4random();
    EXPECT_EQ(0, qtaguid_tagSocket(sockfd, tag, uid));
    EXPECT_GE(2, getCtrlRefCnt(tag, uid));
    close(sockfd);
    EXPECT_EQ(-ENOENT, getCtrlRefCnt(tag, uid));
}

int main(int argc, char **argv) {
      testing::InitGoogleTest(&argc, argv);

      return RUN_ALL_TESTS();
}
