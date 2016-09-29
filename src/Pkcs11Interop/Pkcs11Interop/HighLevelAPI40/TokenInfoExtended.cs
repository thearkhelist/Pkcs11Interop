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
using Net.Pkcs11Interop.LowLevelAPI40;

namespace Net.Pkcs11Interop.HighLevelAPI40
{
    /// <summary>
    /// Information about a token
    /// </summary>
    public class TokenInfoExtended
    {
        /// <summary>
        /// PKCS#11 handle of slot
        /// </summary>
        private uint _slotId = CK.CK_INVALID_HANDLE;

        /// <summary>
        /// PKCS#11 handle of slot
        /// </summary>
        public uint SlotId
        {
            get
            {
                return _slotId;
            }
        }

        /// <summary>
        /// init this field by size of this structure
        /// </summary>
        private uint _SizeofThisStructure = 0;

        /// <summary>
        /// init this field by size of this structure
        /// </summary>
        public uint SizeofThisStructure
        {
            get
            {
                return _SizeofThisStructure;
            }
        }

        /// <summary>
        /// type of token
        /// </summary>
        private uint _TokenType = 0;

        /// <summary>
        /// type of token
        /// </summary>
        public uint TokenType
        {
            get
            {
                return _TokenType;
            }
        }

        /// <summary>
        /// exchange protocol number
        /// </summary>
        private uint _ProtocolNumber = 0;

        /// <summary>
        /// exchange protocol number
        /// </summary>
        public uint ProtocolNumber
        {
            get
            {
                return _ProtocolNumber;
            }
        }

        /// <summary>
        /// microcode number
        /// </summary>
        private uint _MicrocodeNumber = 0;

        /// <summary>
        /// microcode number
        /// </summary>
        public uint MicrocodeNumber
        {
            get
            {
                return _MicrocodeNumber;
            }
        }

        /// <summary>
        /// order number
        /// </summary>
        private uint _OrderNumber = 0;

        /// <summary>
        /// order number
        /// </summary>
        public uint OrderNumber
        {
            get
            {
                return _OrderNumber;
            }
        }

        /// <summary>
        /// Serial number of the device
        /// </summary>
        private string _serialNumber = null;

        /// <summary>
        /// Serial number of the device
        /// </summary>
        public string SerialNumber
        {
            get
            {
                return _serialNumber;
            }
        }

        /// <summary>
        /// Bit flags indicating capabilities and status of the device
        /// </summary>
        private uint _tokenFlags = 0;

        /// <summary>
        /// Bit flags indicating capabilities and status of the device
        /// </summary>
        public uint TokenFlags
        {
            get
            {
                return _tokenFlags;
            }
        }

        /// <summary>
        /// max count of unsuccessful login attempts
        /// </summary>
        private uint _MaxAdminRetryCount = 0;

        /// <summary>
        /// max count of unsuccessful login attempts
        /// </summary>
        public uint MaxAdminRetryCount
        {
            get
            {
                return _MaxAdminRetryCount;
            }
        }

        /// <summary>
        /// count of unsuccessful attempts left (for administrator PIN)
        /// </summary>
        private uint _AdminRetryCountLeft = 0;

        /// <summary>
        /// count of unsuccessful attempts left (for administrator PIN)
        /// </summary>
        public uint AdminRetryCountLeft
        {
            get
            {
                return _AdminRetryCountLeft;
            }
        }

        /// <summary>
        /// min counts of unsuccessful login attempts
        /// </summary>
        private uint _MaxUserRetryCount = 0;

        /// <summary>
        /// min counts of unsuccessful login attempts
        /// </summary>
        public uint MaxUserRetryCount
        {
            get
            {
                return _MaxUserRetryCount;
            }
        }

        /// <summary>
        /// count of unsuccessful attempts left (for user PIN)
        /// </summary>
        private uint _UserRetryCountLeft = 0;

        /// <summary>
        /// count of unsuccessful attempts left (for user PIN)
        /// </summary>
        public uint UserRetryCountLeft
        {
            get
            {
                return _UserRetryCountLeft;
            }
        }

        /// <summary>
        /// Maximum length in bytes of the Admin PIN
        /// </summary>
        private uint _maxAdminPinLen = 0;

        /// <summary>
        /// Maximum length in bytes of the Admin PIN
        /// </summary>
        public uint MaxAdminPinLen
        {
            get
            {
                return _maxAdminPinLen;
            }
        }

        /// <summary>
        /// Minimum length in bytes of the Admin PIN
        /// </summary>
        private uint _minAdminPinLen = 0;

        /// <summary>
        /// Minimum length in bytes of the Admin PIN
        /// </summary>
        public uint MinAdminPinLen
        {
            get
            {
                return _minAdminPinLen;
            }
        }        
        /// <summary>
        /// Maximum length in bytes of the User PIN
        /// </summary>
        private uint _maxUserPinLen = 0;

        /// <summary>
        /// Maximum length in bytes of the User PIN
        /// </summary>
        public uint MaxUserPinLen
        {
            get
            {
                return _maxUserPinLen;
            }
        }

        /// <summary>
        /// Minimum length in bytes of the User PIN
        /// </summary>
        private uint _minUserPinLen = 0;

        /// <summary>
        /// Minimum length in bytes of the User PIN
        /// </summary>
        public uint MinUserPinLen
        {
            get
            {
                return _minUserPinLen;
            }
        }

        /// <summary>
        /// The total amount of memory on the token
        /// </summary>
        private uint _totalMemory = 0;

        /// <summary>
        /// The total amount of memory on the token in bytes
        /// </summary>
        public uint TotalMemory
        {
            get
            {
                return _totalMemory;
            }
        }

        /// <summary>
        /// The amount of free (unused) memory on the token in bytes
        /// </summary>
        private uint _freeMemory = 0;

        /// <summary>
        /// The amount of free (unused) memory on the token in byte
        /// </summary>
        public uint FreeMemory
        {
            get
            {
                return _freeMemory;
            }
        }

        /// <summary>
        /// ATR
        /// </summary>
        private string _ATR = null;

        /// <summary>
        /// ATR
        /// </summary>
        public string ATR
        {
            get
            {
                return _ATR;
            }
        }

        /// <summary>
        /// ATRLen
        /// </summary>
        private uint _ATRLen = 0;

        /// <summary>
        /// ATRLen
        /// </summary>
        public uint ATRLen
        {
            get
            {
                return _ATRLen;
            }
        }

        /// <summary>
        /// Class of token
        /// </summary>
        private uint _TokenClass = 0;

        /// <summary>
        /// Class of token
        /// </summary>
        public uint TokenClass
        {
            get
            {
                return _TokenClass;
            }
        }

        private uint _BatteryVoltage = 0;

        /// <summary>
        /// Battery Voltage
        /// </summary>
        public uint BatteryVoltage
        {
            get
            {
                return _BatteryVoltage;
            }
        }

        /// <summary>
        /// Body color of the token
        /// </summary>
        private uint _BodyColor = 0;

        /// <summary>
        /// Body color of the token
        /// </summary>
        public uint BodyColor
        {
            get
            {
                return _BodyColor;
            }
        }

        /// <summary>
        /// Checksum of token firmware
        /// </summary>
        private uint _ulFirmwareChecksum = 0;

        /// <summary>
        /// Checksum of token firmware
        /// </summary>
        public uint ulFirmwareChecksum
        {
            get
            {
                return _ulFirmwareChecksum;
            }
        }
      
        /// <summary>
        /// Converts low level CK_TOKEN_INFO structure to high level TokenInfo class
        /// </summary>
        /// <param name="slotId">PKCS#11 handle of slot</param>
        /// <param name="ck_token_info">Low level CK_TOKEN_INFO structure</param>
        internal TokenInfoExtended(uint slotId, CK_TOKEN_INFO_EXTENDED ck_token_info)
        {
            _slotId = slotId;
            _SizeofThisStructure = ck_token_info.SizeofThisStructure;
            _TokenType = ck_token_info.TokenType;
            _ProtocolNumber = ck_token_info.ProtocolNumber;
            _MicrocodeNumber = ck_token_info.MicrocodeNumber;
            _serialNumber = ConvertUtils.BytesToUtf8String(ck_token_info.SerialNumber, true);
            _tokenFlags = ck_token_info.Flags;
            _MaxAdminRetryCount = ck_token_info.MaxAdminRetryCount;
            _AdminRetryCountLeft = ck_token_info.AdminRetryCountLeft;
            _MaxUserRetryCount = ck_token_info.MaxUserRetryCount;
            _UserRetryCountLeft = ck_token_info.UserRetryCountLeft;
            _maxAdminPinLen = ck_token_info.MaxAdminLen;
            _minAdminPinLen = ck_token_info.MinAdminPinLen;
            _maxUserPinLen = ck_token_info.MaxUserPinLen;
            _minUserPinLen = ck_token_info.MinUserPinLen;
            _totalMemory = ck_token_info.TotalMemory;
            _freeMemory = ck_token_info.FreeMemory;
            _ATR = ConvertUtils.BytesToUtf8String(ck_token_info.ATR, true);
            _ATRLen = ck_token_info.ATRLen;
            _TokenClass = ck_token_info.TokenClass;
            _BatteryVoltage = ck_token_info.BatteryVoltage;
            _BodyColor = ck_token_info.BodyColor;
            _ulFirmwareChecksum = ck_token_info.ulFirmwareChecksum;
                         
        }
    }
}
