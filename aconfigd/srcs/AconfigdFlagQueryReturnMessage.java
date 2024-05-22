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

import java.util.Objects;

/** @hide */
public class AconfigdFlagQueryReturnMessage {

    private String mPackageName;
    private String mFlagName;
    private String mServerFlagValue;
    private String mLocalFlagValue;
    private String mBootFlagValue;
    private String mDefaultFlagValue;
    private boolean mHasServerOverride;
    private boolean mHashLocalOverride;
    private boolean mIsReadWrite;

    AconfigdFlagQueryReturnMessage(Builder builder) {
        mPackageName = builder.mPackageName;
        mFlagName = builder.mFlagName;
        mServerFlagValue = builder.mServerFlagValue;
        mLocalFlagValue = builder.mLocalFlagValue;
        mBootFlagValue = builder.mBootFlagValue;
        mDefaultFlagValue = builder.mDefaultFlagValue;
        mHasServerOverride = builder.mHasServerOverride;
        mHashLocalOverride = builder.mHashLocalOverride;
        mIsReadWrite = builder.mIsReadWrite;
    }

    public String getFullFlagName() {
        StringBuilder ret = new StringBuilder(mPackageName);
        return ret.append('.').append(mFlagName).toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof AconfigdFlagQueryReturnMessage)) {
            return false;
        }
        AconfigdFlagQueryReturnMessage other = (AconfigdFlagQueryReturnMessage) obj;
        return Objects.equals(mPackageName, other.mPackageName)
                && Objects.equals(mFlagName, other.mFlagName)
                && Objects.equals(mServerFlagValue, other.mServerFlagValue)
                && Objects.equals(mLocalFlagValue, other.mLocalFlagValue)
                && Objects.equals(mBootFlagValue, other.mBootFlagValue)
                && Objects.equals(mDefaultFlagValue, other.mDefaultFlagValue)
                && mHasServerOverride == other.mHasServerOverride
                && mHashLocalOverride == other.mHashLocalOverride
                && mIsReadWrite == other.mIsReadWrite;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                mPackageName,
                mFlagName,
                mServerFlagValue,
                mLocalFlagValue,
                mBootFlagValue,
                mDefaultFlagValue,
                mHasServerOverride,
                mHashLocalOverride,
                mIsReadWrite);
    }

    public static class Builder {
        private String mPackageName;
        private String mFlagName;
        private String mServerFlagValue;
        private String mLocalFlagValue;
        private String mBootFlagValue;
        private String mDefaultFlagValue;
        private boolean mHasServerOverride;
        private boolean mHashLocalOverride;
        private boolean mIsReadWrite;

        public Builder setPackageName(String packageName) {
            mPackageName = packageName;
            return this;
        }

        public Builder setFlagName(String flagName) {
            mFlagName = flagName;
            return this;
        }

        public Builder setServerFlagValue(String serverFlagValue) {
            setvalue(mServerFlagValue, serverFlagValue);
            return this;
        }

        public Builder setLocalFlagValue(String localFlagValue) {
            setvalue(mLocalFlagValue, localFlagValue);
            return this;
        }

        public Builder setBootFlagValue(String bootFlagValue) {
            setvalue(mBootFlagValue, bootFlagValue);
            return this;
        }

        public Builder setDefaultFlagValue(String defaultFlagValue) {
            setvalue(mDefaultFlagValue, defaultFlagValue);
            return this;
        }

        public Builder setHasServerOverride(boolean hasServerOverride) {
            mHasServerOverride = hasServerOverride;
            return this;
        }

        public Builder setHashLocalOverride(boolean hashLocalOverride) {
            mHashLocalOverride = hashLocalOverride;
            return this;
        }

        public Builder setIsReadWrite(boolean isReadWrite) {
            mIsReadWrite = isReadWrite;
            return this;
        }

        public AconfigdFlagQueryReturnMessage build() {
            return new AconfigdFlagQueryReturnMessage(this);
        }

        private void setvalue(String current, String target) {
            current = target.isEmpty() ? null : target;
        }
    }
}
