/*
 *  Copyright 2012-2016 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

using System;
using Net.Pkcs11Interop.Common;

namespace Net.Pkcs11Interop.HighLevelAPI
{
    /// <summary>
    /// Information about a token
    /// </summary>
    public class TokenInfoExtended
    {
        /// <summary>
        /// Platform specific TokenInfo
        /// </summary>
        private HighLevelAPI40.TokenInfoExtended _tokenInfo40 = null;

        /// <summary>
        /// Platform specific TokenInfo
        /// </summary>
        private HighLevelAPI41.TokenInfoExtended _tokenInfo41 = null;

        /// <summary>
        /// Platform specific TokenInfo
        /// </summary>
        private HighLevelAPI80.TokenInfoExtended _tokenInfo80 = null;

        /// <summary>
        /// Platform specific TokenInfo
        /// </summary>
        private HighLevelAPI81.TokenInfoExtended _tokenInfo81 = null;

        /// <summary>
        /// PKCS#11 handle of slot
        /// </summary>
        public uint SlotId
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.SlotId : _tokenInfo41.SlotId;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.SlotId : _tokenInfo81.SlotId;
            }
        }

        /// <summary>
        /// Application-defined SizeofThisStructure, assigned during token initialization
        /// </summary>
        public uint SizeofThisStructure
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.SizeofThisStructure : _tokenInfo41.SizeofThisStructure;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.SizeofThisStructure : _tokenInfo81.SizeofThisStructure;
            }
        }

        /// <summary>
        /// TokenType
        /// </summary>
        public uint TokenType
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.TokenType : _tokenInfo41.TokenType;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.TokenType : _tokenInfo81.TokenType;
            }
        }

        /// <summary>
        /// Protocol Number of the device
        /// </summary>
        public uint ProtocolNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.ProtocolNumber : _tokenInfo41.ProtocolNumber;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.ProtocolNumber : _tokenInfo81.ProtocolNumber;
            }
        }

        /// <summary>
        /// Microcode Number of the device
        /// </summary>
        public uint MicrocodeNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.MicrocodeNumber : _tokenInfo41.MicrocodeNumber;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.MicrocodeNumber : _tokenInfo81.MicrocodeNumber;
            }
        }

        /// <summary>
        /// Order Number of the device
        /// </summary>
        public uint OrderNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.OrderNumber : _tokenInfo41.OrderNumber;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.OrderNumber : _tokenInfo81.OrderNumber;
            }
        }


        /// <summary>
        /// Serial Number
        /// </summary>
        public string SerialNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.SerialNumber : _tokenInfo41.SerialNumber;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.SerialNumber : _tokenInfo81.SerialNumber;
            }
        }

        /// <summary>
        /// Token Flags
        /// </summary>
        public uint TokenFlags
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.TokenFlags : _tokenInfo41.TokenFlags;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.TokenFlags : _tokenInfo81.TokenFlags;
            }
        }

        /// <summary>
        /// MaxAdminRetryCount
        /// </summary>
        public uint MaxAdminRetryCount
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.MaxAdminRetryCount : _tokenInfo41.MaxAdminRetryCount;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.MaxAdminRetryCount : _tokenInfo81.MaxAdminRetryCount;
            }
        }

        /// <summary>
        /// AdminRetryCountLeft
        /// </summary>
        public uint AdminRetryCountLeft
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.AdminRetryCountLeft : _tokenInfo41.AdminRetryCountLeft;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.AdminRetryCountLeft : _tokenInfo81.AdminRetryCountLeft;
            }
        }

        /// <summary>
        /// MaxUserRetryCount
        /// </summary>
        public uint MaxUserRetryCount
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.MaxUserRetryCount : _tokenInfo41.MaxUserRetryCount;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.MaxUserRetryCount : _tokenInfo81.MaxUserRetryCount;
            }
        }

        /// <summary>
        /// UserRetryCountLeft
        /// </summary>
        public uint UserRetryCountLeft
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.UserRetryCountLeft : _tokenInfo41.UserRetryCountLeft;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.UserRetryCountLeft : _tokenInfo81.UserRetryCountLeft;
            }
        }

        /// <summary>
        /// MaxAdminPinLen
        /// </summary>
        public uint MaxAdminPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.MaxAdminPinLen : _tokenInfo41.MaxAdminPinLen;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.MaxAdminPinLen : _tokenInfo81.MaxAdminPinLen;
            }
        }

        /// <summary>
        /// MinAdminPinLen
        /// </summary>
        public uint MinAdminPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.MinAdminPinLen : _tokenInfo41.MinAdminPinLen;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.MinAdminPinLen : _tokenInfo81.MinAdminPinLen;
            }
        }

        /// <summary>
        /// MaxUserPinLen
        /// </summary>
        public uint MaxUserPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.MaxUserPinLen : _tokenInfo41.MaxUserPinLen;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.MaxUserPinLen : _tokenInfo81.MaxUserPinLen;
            }
        }

        /// <summary>
        /// MinUserPinLen
        /// </summary>
        public uint MinUserPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.MinUserPinLen : _tokenInfo41.MinUserPinLen;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.MinUserPinLen : _tokenInfo81.MinUserPinLen;
            }
        }

        /// <summary>
        /// TotalMemory
        /// </summary>
        public uint TotalMemory
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.TotalMemory : _tokenInfo41.TotalMemory;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.TotalMemory : _tokenInfo81.TotalMemory;
            }
        }

        /// <summary>
        /// FreeMemory
        /// </summary>
        public uint FreeMemory
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.FreeMemory : _tokenInfo41.FreeMemory;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.FreeMemory : _tokenInfo81.FreeMemory;
            }
        }

        /// <summary>
        /// ATR
        /// </summary>
        public string ATR
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.ATR : _tokenInfo41.ATR;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.ATR : _tokenInfo81.ATR;
            }
        }

        /// <summary>
        /// ATRLen
        /// </summary>
        public uint ATRLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.ATRLen : _tokenInfo41.ATRLen;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.ATRLen : _tokenInfo81.ATRLen;
            }
        }

        /// <summary>
        /// TokenClass
        /// </summary>
        public uint TokenClass
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.TokenClass : _tokenInfo41.TokenClass;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.TokenClass : _tokenInfo81.TokenClass;
            }
        }

        /// <summary>
        /// BatteryVoltage
        /// </summary>
        public uint BatteryVoltage
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.BatteryVoltage : _tokenInfo41.BatteryVoltage;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.BatteryVoltage : _tokenInfo81.BatteryVoltage;
            }
        }

        /// <summary>
        /// BodyColor
        /// </summary>
        public uint BodyColor
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.BodyColor : _tokenInfo41.BodyColor;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.BodyColor : _tokenInfo81.BodyColor;
            }
        }

        /// <summary>
        /// ulFirmwareChecksum
        /// </summary>
        public uint ulFirmwareChecksum
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                    return (Platform.StructPackingSize == 0) ? _tokenInfo40.ulFirmwareChecksum : _tokenInfo41.ulFirmwareChecksum;
                else
                    return (Platform.StructPackingSize == 0) ? _tokenInfo80.ulFirmwareChecksum : _tokenInfo81.ulFirmwareChecksum;
            }
        }

        /// <summary>
        /// Converts platform specific TokenInfo to platfrom neutral TokenInfo
        /// </summary>
        /// <param name="tokenInfo">Platform specific TokenInfo</param>
        internal TokenInfoExtended(HighLevelAPI40.TokenInfoExtended tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            _tokenInfo40 = tokenInfo;
        }

        /// <summary>
        /// Converts platform specific TokenInfo to platfrom neutral TokenInfo
        /// </summary>
        /// <param name="tokenInfo">Platform specific TokenInfo</param>
        internal TokenInfoExtended(HighLevelAPI41.TokenInfoExtended tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            _tokenInfo41 = tokenInfo;
        }

        /// <summary>
        /// Converts platform specific TokenInfo to platfrom neutral TokenInfo
        /// </summary>
        /// <param name="tokenInfo">Platform specific TokenInfo</param>
        internal TokenInfoExtended(HighLevelAPI80.TokenInfoExtended tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            _tokenInfo80 = tokenInfo;
        }

        /// <summary>
        /// Converts platform specific TokenInfo to platfrom neutral TokenInfo
        /// </summary>
        /// <param name="tokenInfo">Platform specific TokenInfo</param>
        internal TokenInfoExtended(HighLevelAPI81.TokenInfoExtended tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException("tokenInfo");

            _tokenInfo81 = tokenInfo;
        }
    }
}
