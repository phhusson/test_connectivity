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

import static android.system.OsConstants.ETH_P_IPV6;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.net.MacAddress;
import android.os.Build;
import android.system.ErrnoException;
import android.system.OsConstants;
import android.util.ArrayMap;

import androidx.test.runner.AndroidJUnit4;

import com.android.testutils.DevSdkIgnoreRule.IgnoreUpTo;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.net.InetAddress;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;


@RunWith(AndroidJUnit4.class)
@IgnoreUpTo(Build.VERSION_CODES.R)
public final class BpfMapTest {
    // Sync from packages/modules/Connectivity/Tethering/bpf_progs/offload.c.
    private static final int TEST_MAP_SIZE = 16;
    private static final String TETHER_DOWNSTREAM6_FS_PATH =
            "/sys/fs/bpf/tethering/map_test_tether_downstream6_map";

    private ArrayMap<TetherDownstream6Key, TetherDownstream6Value> mTestData;

    @BeforeClass
    public static void setupOnce() {
        System.loadLibrary("tetherutilsjni");
    }

    @Before
    public void setUp() throws Exception {
        // TODO: Simply the test map creation and deletion.
        // - Make the map a class member (mTestMap)
        // - Open the test map RW in setUp
        // - Close the test map in tearDown.
        cleanTestMap();

        mTestData = new ArrayMap<>();
        mTestData.put(createTetherDownstream6Key(101, "2001:db8::1"),
                createTetherDownstream6Value(11, "00:00:00:00:00:0a", "11:11:11:00:00:0b",
                ETH_P_IPV6, 1280));
        mTestData.put(createTetherDownstream6Key(102, "2001:db8::2"),
                createTetherDownstream6Value(22, "00:00:00:00:00:0c", "22:22:22:00:00:0d",
                ETH_P_IPV6, 1400));
        mTestData.put(createTetherDownstream6Key(103, "2001:db8::3"),
                createTetherDownstream6Value(33, "00:00:00:00:00:0e", "33:33:33:00:00:0f",
                ETH_P_IPV6, 1500));
    }

    @After
    public void tearDown() throws Exception {
        cleanTestMap();
    }

    private BpfMap<TetherDownstream6Key, TetherDownstream6Value> getTestMap() throws Exception {
        return new BpfMap<>(
                TETHER_DOWNSTREAM6_FS_PATH, BpfMap.BPF_F_RDWR,
                TetherDownstream6Key.class, TetherDownstream6Value.class);
    }

    private void cleanTestMap() throws Exception {
        try (BpfMap<TetherDownstream6Key, TetherDownstream6Value> bpfMap = getTestMap()) {
            bpfMap.forEach((key, value) -> {
                try {
                    assertTrue(bpfMap.deleteEntry(key));
                } catch (ErrnoException e) {
                    fail("Fail to delete the key " + key + ": " + e);
                }
            });
            assertNull(bpfMap.getFirstKey());
        }
    }

    private TetherDownstream6Key createTetherDownstream6Key(long iif, String address)
            throws Exception {
        final InetAddress ipv6Address = InetAddress.getByName(address);

        return new TetherDownstream6Key(iif, ipv6Address.getAddress());
    }

    private TetherDownstream6Value createTetherDownstream6Value(long oif, String src, String dst,
            int proto, int pmtu) throws Exception {
        final MacAddress srcMac = MacAddress.fromString(src);
        final MacAddress dstMac = MacAddress.fromString(dst);

        return new TetherDownstream6Value(oif, dstMac, srcMac, proto, pmtu);
    }

    @Test
    public void testGetFd() throws Exception {
        try (BpfMap readOnlyMap = new BpfMap<>(TETHER_DOWNSTREAM6_FS_PATH, BpfMap.BPF_F_RDONLY,
                TetherDownstream6Key.class, TetherDownstream6Value.class)) {
            assertNotNull(readOnlyMap);
            try {
                readOnlyMap.insertEntry(mTestData.keyAt(0), mTestData.valueAt(0));
                fail("Writing RO map should throw ErrnoException");
            } catch (ErrnoException expected) {
                assertEquals(OsConstants.EPERM, expected.errno);
            }
        }
        try (BpfMap writeOnlyMap = new BpfMap<>(TETHER_DOWNSTREAM6_FS_PATH, BpfMap.BPF_F_WRONLY,
                TetherDownstream6Key.class, TetherDownstream6Value.class)) {
            assertNotNull(writeOnlyMap);
            try {
                writeOnlyMap.getFirstKey();
                fail("Reading WO map should throw ErrnoException");
            } catch (ErrnoException expected) {
                assertEquals(OsConstants.EPERM, expected.errno);
            }
        }
        try (BpfMap readWriteMap = new BpfMap<>(TETHER_DOWNSTREAM6_FS_PATH, BpfMap.BPF_F_RDWR,
                TetherDownstream6Key.class, TetherDownstream6Value.class)) {
            assertNotNull(readWriteMap);
        }
    }

    @Test
    public void testGetFirstKey() throws Exception {
        try (BpfMap<TetherDownstream6Key, TetherDownstream6Value> bpfMap = getTestMap()) {
            // getFirstKey on an empty map returns null.
            assertFalse(bpfMap.containsKey(mTestData.keyAt(0)));
            assertNull(bpfMap.getFirstKey());
            assertNull(bpfMap.getValue(mTestData.keyAt(0)));

            // getFirstKey on a non-empty map returns the first key.
            bpfMap.insertEntry(mTestData.keyAt(0), mTestData.valueAt(0));
            assertEquals(mTestData.keyAt(0), bpfMap.getFirstKey());
        }
    }

    @Test
    public void testGetNextKey() throws Exception {
        try (BpfMap<TetherDownstream6Key, TetherDownstream6Value> bpfMap = getTestMap()) {
            // [1] If the passed-in key is not found on empty map, return null.
            final TetherDownstream6Key nonexistentKey =
                    createTetherDownstream6Key(1234, "2001:db8::10");
            assertNull(bpfMap.getNextKey(nonexistentKey));

            // [2] If the passed-in key is null on empty map, throw NullPointerException.
            try {
                bpfMap.getNextKey(null);
                fail("Getting next key with null key should throw NullPointerException");
            } catch (NullPointerException expected) { }

            // The BPF map has one entry now.
            final ArrayMap<TetherDownstream6Key, TetherDownstream6Value> resultMap =
                    new ArrayMap<>();
            bpfMap.insertEntry(mTestData.keyAt(0), mTestData.valueAt(0));
            resultMap.put(mTestData.keyAt(0), mTestData.valueAt(0));

            // [3] If the passed-in key is the last key, return null.
            // Because there is only one entry in the map, the first key equals the last key.
            final TetherDownstream6Key lastKey = bpfMap.getFirstKey();
            assertNull(bpfMap.getNextKey(lastKey));

            // The BPF map has two entries now.
            bpfMap.insertEntry(mTestData.keyAt(1), mTestData.valueAt(1));
            resultMap.put(mTestData.keyAt(1), mTestData.valueAt(1));

            // [4] If the passed-in key is found, return the next key.
            TetherDownstream6Key nextKey = bpfMap.getFirstKey();
            while (nextKey != null) {
                if (resultMap.remove(nextKey).equals(nextKey)) {
                    fail("Unexpected result: " + nextKey);
                }
                nextKey = bpfMap.getNextKey(nextKey);
            }
            assertTrue(resultMap.isEmpty());

            // [5] If the passed-in key is not found on non-empty map, return the first key.
            assertEquals(bpfMap.getFirstKey(), bpfMap.getNextKey(nonexistentKey));

            // [6] If the passed-in key is null on non-empty map, throw NullPointerException.
            try {
                bpfMap.getNextKey(null);
                fail("Getting next key with null key should throw NullPointerException");
            } catch (NullPointerException expected) { }
        }
    }

    @Test
    public void testUpdateBpfMap() throws Exception {
        try (BpfMap<TetherDownstream6Key, TetherDownstream6Value> bpfMap = getTestMap()) {

            final TetherDownstream6Key key = mTestData.keyAt(0);
            final TetherDownstream6Value value = mTestData.valueAt(0);
            final TetherDownstream6Value value2 = mTestData.valueAt(1);
            assertFalse(bpfMap.deleteEntry(key));

            // updateEntry will create an entry if it does not exist already.
            bpfMap.updateEntry(key, value);
            assertTrue(bpfMap.containsKey(key));
            final TetherDownstream6Value result = bpfMap.getValue(key);
            assertEquals(value, result);

            // updateEntry will update an entry that already exists.
            bpfMap.updateEntry(key, value2);
            assertTrue(bpfMap.containsKey(key));
            final TetherDownstream6Value result2 = bpfMap.getValue(key);
            assertEquals(value2, result2);

            assertTrue(bpfMap.deleteEntry(key));
            assertFalse(bpfMap.containsKey(key));
        }
    }

    @Test
    public void testInsertReplaceEntry() throws Exception {
        try (BpfMap<TetherDownstream6Key, TetherDownstream6Value> bpfMap = getTestMap()) {

            final TetherDownstream6Key key = mTestData.keyAt(0);
            final TetherDownstream6Value value = mTestData.valueAt(0);
            final TetherDownstream6Value value2 = mTestData.valueAt(1);

            try {
                bpfMap.replaceEntry(key, value);
                fail("Replacing non-existent key " + key + " should throw NoSuchElementException");
            } catch (NoSuchElementException expected) { }
            assertFalse(bpfMap.containsKey(key));

            bpfMap.insertEntry(key, value);
            assertTrue(bpfMap.containsKey(key));
            final TetherDownstream6Value result = bpfMap.getValue(key);
            assertEquals(value, result);
            try {
                bpfMap.insertEntry(key, value);
                fail("Inserting existing key " + key + " should throw IllegalStateException");
            } catch (IllegalStateException expected) { }

            bpfMap.replaceEntry(key, value2);
            assertTrue(bpfMap.containsKey(key));
            final TetherDownstream6Value result2 = bpfMap.getValue(key);
            assertEquals(value2, result2);
        }
    }

    @Test
    public void testIterateBpfMap() throws Exception {
        try (BpfMap<TetherDownstream6Key, TetherDownstream6Value> bpfMap = getTestMap()) {
            final ArrayMap<TetherDownstream6Key, TetherDownstream6Value> resultMap =
                    new ArrayMap<>(mTestData);

            for (int i = 0; i < resultMap.size(); i++) {
                bpfMap.insertEntry(resultMap.keyAt(i), resultMap.valueAt(i));
            }

            bpfMap.forEach((key, value) -> {
                if (!value.equals(resultMap.remove(key))) {
                    fail("Unexpected result: " + key + ", value: " + value);
                }
            });
            assertTrue(resultMap.isEmpty());
        }
    }

    @Test
    public void testIterateEmptyMap() throws Exception {
        try (BpfMap<TetherDownstream6Key, TetherDownstream6Value> bpfMap = getTestMap()) {
            // Can't use an int because variables used in a lambda must be final.
            final AtomicInteger count = new AtomicInteger();
            bpfMap.forEach((key, value) -> count.incrementAndGet());
            // Expect that the consumer was never called.
            assertEquals(0, count.get());
        }
    }

    @Test
    public void testIterateDeletion() throws Exception {
        try (BpfMap<TetherDownstream6Key, TetherDownstream6Value> bpfMap = getTestMap()) {
            final ArrayMap<TetherDownstream6Key, TetherDownstream6Value> resultMap =
                    new ArrayMap<>(mTestData);

            for (int i = 0; i < resultMap.size(); i++) {
                bpfMap.insertEntry(resultMap.keyAt(i), resultMap.valueAt(i));
            }

            // Can't use an int because variables used in a lambda must be final.
            final AtomicInteger count = new AtomicInteger();
            bpfMap.forEach((key, value) -> {
                try {
                    assertTrue(bpfMap.deleteEntry(key));
                } catch (ErrnoException e) {
                    fail("Fail to delete key " + key + ": " + e);
                }
                if (!value.equals(resultMap.remove(key))) {
                    fail("Unexpected result: " + key + ", value: " + value);
                }
                count.incrementAndGet();
            });
            assertEquals(3, count.get());
            assertTrue(resultMap.isEmpty());
            assertNull(bpfMap.getFirstKey());
        }
    }

    @Test
    public void testInsertOverflow() throws Exception {
        try (BpfMap<TetherDownstream6Key, TetherDownstream6Value> bpfMap = getTestMap()) {
            final ArrayMap<TetherDownstream6Key, TetherDownstream6Value> testData =
                    new ArrayMap<>();

            // Build test data for TEST_MAP_SIZE + 1 entries.
            for (int i = 1; i <= TEST_MAP_SIZE + 1; i++) {
                testData.put(createTetherDownstream6Key(i, "2001:db8::1"),
                        createTetherDownstream6Value(100, "de:ad:be:ef:00:01", "de:ad:be:ef:00:02",
                        ETH_P_IPV6, 1500));
            }

            // Insert #TEST_MAP_SIZE test entries to the map. The map has reached the limit.
            for (int i = 0; i < TEST_MAP_SIZE; i++) {
                bpfMap.insertEntry(testData.keyAt(i), testData.valueAt(i));
            }

            // The map won't allow inserting any more entries.
            try {
                bpfMap.insertEntry(testData.keyAt(TEST_MAP_SIZE), testData.valueAt(TEST_MAP_SIZE));
                fail("Writing too many entries should throw ErrnoException");
            } catch (ErrnoException expected) {
                // Expect that can't insert the entry anymore because the number of elements in the
                // map reached the limit. See man-pages/bpf.
                assertEquals(OsConstants.E2BIG, expected.errno);
            }
        }
    }
}
