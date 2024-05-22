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

package android.aconfigd;

import android.aconfigd.Aconfigd.StorageRequestMessage;
import android.aconfigd.Aconfigd.StorageRequestMessages;
import android.aconfigd.Aconfigd.StorageReturnMessage;
import android.aconfigd.Aconfigd.StorageReturnMessages;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.util.Slog;
import android.util.proto.ProtoInputStream;
import android.util.proto.ProtoOutputStream;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Map;

/** @hide */
public class AconfigdJavaUtils {

    private static String TAG = "AconfigdJavaUtils";

    /**
     * deserialize a flag input proto stream and log
     *
     * @param proto
     * @hide
     */
    public static void writeFlagOverrideRequest(
            ProtoOutputStream proto,
            String packageName,
            String flagName,
            String flagValue,
            boolean isLocal) {
        long msgsToken = proto.start(StorageRequestMessages.MSGS);
        long msgToken = proto.start(StorageRequestMessage.FLAG_OVERRIDE_MESSAGE);
        proto.write(StorageRequestMessage.FlagOverrideMessage.PACKAGE_NAME, packageName);
        proto.write(StorageRequestMessage.FlagOverrideMessage.FLAG_NAME, flagName);
        proto.write(StorageRequestMessage.FlagOverrideMessage.FLAG_VALUE, flagValue);
        proto.write(StorageRequestMessage.FlagOverrideMessage.IS_LOCAL, isLocal);
        proto.end(msgToken);
        proto.end(msgsToken);
    }

    /**
     * deserialize a flag input proto stream and log
     *
     * @param proto
     * @hide
     */
    public static void parseAndLogAconfigdReturn(ProtoInputStream proto) throws IOException {
        while (true) {
            switch (proto.nextField()) {
                case (int) StorageReturnMessages.MSGS:
                    long msgsToken = proto.start(StorageReturnMessages.MSGS);
                    switch (proto.nextField()) {
                        case (int) StorageReturnMessage.FLAG_OVERRIDE_MESSAGE:
                            Slog.i(TAG, "successfully handled override requests");
                            long msgToken = proto.start(StorageReturnMessage.FLAG_OVERRIDE_MESSAGE);
                            proto.end(msgToken);
                            break;
                        case (int) StorageReturnMessage.ERROR_MESSAGE:
                            String errmsg = proto.readString(StorageReturnMessage.ERROR_MESSAGE);
                            Slog.i(TAG, "override request failed: " + errmsg);
                            break;
                        case ProtoInputStream.NO_MORE_FIELDS:
                            break;
                        default:
                            Slog.e(
                                    TAG,
                                    "invalid message type, expecting only flag override return or"
                                            + " error message");
                            break;
                    }
                    proto.end(msgsToken);
                    break;
                case ProtoInputStream.NO_MORE_FIELDS:
                    return;
                default:
                    Slog.e(TAG, "invalid message type, expect storage return message");
                    break;
            }
        }
    }

    /**
     * send request to aconfigd
     *
     * @param requests stream of requests
     * @hide
     */
    public static ProtoInputStream sendAconfigdRequests(ProtoOutputStream requests) {
        // connect to aconfigd socket
        LocalSocket client = new LocalSocket();
        try {
            client.connect(
                    new LocalSocketAddress("aconfigd", LocalSocketAddress.Namespace.RESERVED));
            Slog.i(TAG, "connected to aconfigd socket");
        } catch (IOException ioe) {
            Slog.i(TAG, "failed to connect to aconfigd socket", ioe);
            return null;
        }

        DataInputStream inputStream = null;
        DataOutputStream outputStream = null;
        try {
            inputStream = new DataInputStream(client.getInputStream());
            outputStream = new DataOutputStream(client.getOutputStream());
        } catch (IOException ioe) {
            Slog.e(TAG, "failed to get local socket iostreams", ioe);
            return null;
        }

        // send requests
        try {
            byte[] requests_bytes = requests.getBytes();
            outputStream.writeInt(requests_bytes.length);
            outputStream.write(requests_bytes, 0, requests_bytes.length);
            Slog.i(TAG, "flag override requests sent to aconfigd");
        } catch (IOException ioe) {
            Slog.e(TAG, "failed to send requests to aconfigd", ioe);
            return null;
        }

        // read return
        try {
            int num_bytes = inputStream.readInt();
            ProtoInputStream returns = new ProtoInputStream(inputStream);
            Slog.i(TAG, "received " + num_bytes + " bytes back from aconfigd");
            return returns;
        } catch (IOException ioe) {
            Slog.e(TAG, "failed to read requests return from aconfigd", ioe);
            return null;
        }
    }

    /**
     * this method will new flag value into new storage, and stage the new values
     *
     * @param propsToStage the map of flags <namespace, <flagName, value>>
     * @param isLocal indicates whether this is a local override
     * @hide
     */
    public static void stageFlagsInNewStorage(
            Map<String, Map<String, String>> propsToStage, boolean isLocal) {
        // write aconfigd requests proto to proto output stream
        int num_requests = 0;
        ProtoOutputStream requests = new ProtoOutputStream();
        for (Map.Entry<String, Map<String, String>> entry : propsToStage.entrySet()) {
            String actualNamespace = entry.getKey();
            Map<String, String> flagValuesToStage = entry.getValue();
            for (String fullFlagName : flagValuesToStage.keySet()) {
                String stagedValue = flagValuesToStage.get(fullFlagName);
                int idx = fullFlagName.lastIndexOf(".");
                if (idx == -1) {
                    Slog.i(TAG, "invalid flag name: " + fullFlagName);
                    continue;
                }
                String packageName = fullFlagName.substring(0, idx);
                String flagName = fullFlagName.substring(idx + 1);
                writeFlagOverrideRequest(requests, packageName, flagName, stagedValue, isLocal);
                ++num_requests;
            }
        }

        if (num_requests == 0) {
            return;
        }

        // send requests to aconfigd and obtain the return
        ProtoInputStream returns = sendAconfigdRequests(requests);

        // deserialize back using proto input stream
        try {
            parseAndLogAconfigdReturn(returns);
        } catch (IOException ioe) {
            Slog.e(TAG, "failed to parse aconfigd return", ioe);
        }
    }
}
