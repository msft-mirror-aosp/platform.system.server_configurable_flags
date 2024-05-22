/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.aconfigd.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.aconfigd.Aconfigd.StorageReturnMessage;
import android.aconfigd.Aconfigd.StorageReturnMessages;
import android.aconfigd.AconfigdFlagQueryReturnMessage;
import android.aconfigd.AconfigdJavaUtils;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.util.proto.ProtoInputStream;
import android.util.proto.ProtoOutputStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.Map;

@RunWith(JUnit4.class)
public class AconfigdJavaUtilsTest {

    private String mTestAddress = "android.aconfigd.test";
    private LocalServerSocket mLocalServer;
    private LocalSocket mClientLocalSocket;
    private LocalSocket mServerLocalSocket;

    @Before
    public void setUp() throws Exception {
        mLocalServer = new LocalServerSocket(mTestAddress);
        mClientLocalSocket = new LocalSocket();
        mClientLocalSocket.connect(new LocalSocketAddress(mTestAddress));
        mServerLocalSocket = mLocalServer.accept();
    }

    @After
    public void tearDown() throws Exception {
        mServerLocalSocket.close();
        mClientLocalSocket.close();
        mLocalServer.close();
    }

    @Test
    public void testSendAconfigdRequests() throws Exception {
        long fieldFlags =
                ProtoOutputStream.FIELD_COUNT_SINGLE | ProtoOutputStream.FIELD_TYPE_STRING;
        long fieldId = ProtoOutputStream.makeFieldId(1, fieldFlags);

        // client request message
        String testReqMessage = "request test";
        ProtoOutputStream request = new ProtoOutputStream();
        request.write(fieldId, testReqMessage);

        // server return message
        String testRevMessage = "received test";
        ProtoOutputStream serverReturn = new ProtoOutputStream();
        serverReturn.write(fieldId, testRevMessage);
        DataOutputStream outputStream = new DataOutputStream(mServerLocalSocket.getOutputStream());
        outputStream.writeInt(serverReturn.getRawSize());
        outputStream.write(serverReturn.getBytes());

        // validate client received
        ProtoInputStream clientRev =
                AconfigdJavaUtils.sendAconfigdRequests(mClientLocalSocket, request);
        clientRev.nextField();
        assertEquals(testRevMessage, clientRev.readString(fieldId));

        // validate server received
        DataInputStream inputStream = new DataInputStream(mServerLocalSocket.getInputStream());
        inputStream.readInt();
        ProtoInputStream serverRev = new ProtoInputStream(inputStream);
        serverRev.nextField();
        assertEquals(testReqMessage, serverRev.readString(fieldId));
    }

    @Test
    public void testGetFlagsValueInNewStorage() throws Exception {
        ProtoOutputStream serverReturn = new ProtoOutputStream();

        String packageName = "android.acondigd.test";
        String flagName = "test_flag";
        String serverValue = "";
        String localValue = "";
        String bootValue = "true";
        String defaultValue = "true";
        boolean hasServerOverride = false;
        boolean isReadWrite = false;
        boolean hashLocalOverride = false;

        long msgsToken = serverReturn.start(StorageReturnMessages.MSGS);
        long listToken = serverReturn.start(StorageReturnMessage.LIST_STORAGE_MESSAGE);
        long flagToken = serverReturn.start(StorageReturnMessage.ListStorageReturnMessage.FLAGS);
        long queryToken = serverReturn.start(StorageReturnMessage.FLAG_QUERY_MESSAGE);
        serverReturn.write(StorageReturnMessage.FlagQueryReturnMessage.PACKAGE_NAME, packageName);
        serverReturn.write(StorageReturnMessage.FlagQueryReturnMessage.FLAG_NAME, flagName);
        serverReturn.write(
                StorageReturnMessage.FlagQueryReturnMessage.SERVER_FLAG_VALUE, serverValue);
        serverReturn.write(
                StorageReturnMessage.FlagQueryReturnMessage.LOCAL_FLAG_VALUE, localValue);
        serverReturn.write(StorageReturnMessage.FlagQueryReturnMessage.BOOT_FLAG_VALUE, bootValue);
        serverReturn.write(
                StorageReturnMessage.FlagQueryReturnMessage.DEFAULT_FLAG_VALUE, defaultValue);
        serverReturn.write(
                StorageReturnMessage.FlagQueryReturnMessage.HAS_SERVER_OVERRIDE, hasServerOverride);
        serverReturn.write(StorageReturnMessage.FlagQueryReturnMessage.IS_READWRITE, isReadWrite);
        serverReturn.write(
                StorageReturnMessage.FlagQueryReturnMessage.HAS_LOCAL_OVERRIDE, hashLocalOverride);
        serverReturn.end(queryToken);
        serverReturn.end(flagToken);
        serverReturn.end(listToken);
        serverReturn.end(msgsToken);

        DataOutputStream outputStream = new DataOutputStream(mServerLocalSocket.getOutputStream());
        outputStream.writeInt(serverReturn.getRawSize());
        outputStream.write(serverReturn.getBytes());

        AconfigdFlagQueryReturnMessage.Builder builder =
                new AconfigdFlagQueryReturnMessage.Builder();
        AconfigdFlagQueryReturnMessage expectedRet =
                builder.setBootFlagValue(bootValue)
                        .setDefaultFlagValue(defaultValue)
                        .setFlagName(flagName)
                        .setHashLocalOverride(hashLocalOverride)
                        .setHasServerOverride(hasServerOverride)
                        .setIsReadWrite(isReadWrite)
                        .setLocalFlagValue(localValue)
                        .setPackageName(packageName)
                        .setServerFlagValue(serverValue)
                        .build();

        Map<String, AconfigdFlagQueryReturnMessage> flagMap =
                AconfigdJavaUtils.listFlagsValueInNewStorage(mClientLocalSocket);
        assertTrue(flagMap.containsKey(expectedRet.getFullFlagName()));
        assertEquals(expectedRet, flagMap.get(expectedRet.getFullFlagName()));
    }
}
