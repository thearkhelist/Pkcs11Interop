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

using System.Runtime.InteropServices;

namespace Net.Pkcs11Interop.LowLevelAPI80
{
    /// <summary>
    /// Provides information about a token
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_TOKEN_INFO_EXTENDED
    {
        /// <summary>
        /// init this field by size of this structure
        /// </summary>
        public uint SizeofThisStructure;

        /// <summary>
        /// type of token
        /// </summary>
        /// 
        public uint TokenType;

        /// <summary>
        /// exchange protocol number 
        /// </summary>
        public uint ProtocolNumber;

        /// <summary>
        /// microcode number
        /// </summary>
        public uint MicrocodeNumber;

        /// <summary>
        ///  order number
        /// </summary> 
        public uint OrderNumber;
        
        /// <summary>
        /// Character-string serial number of the device. Must be padded with the blank character (‘ ‘). Should not be null-terminated.
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] SerialNumber;

        /// <summary>
        /// Bit flags indicating capabilities and status of the device
        /// </summary>
        public uint Flags;

        /// <summary>
        /// max count of unsuccessful login attempts
        /// </summary>
        public uint MaxAdminRetryCount;

        /// <summary>
        /// count of unsuccessful attempts left (for administrator PIN)
        /// if field equal 0 - that means that PIN is blocked
        /// </summary>
        public uint AdminRetryCountLeft;

        /// <summary>
        ///  min counts of unsuccessful login attempts
        /// </summary>
        public uint MaxUserRetryCount;

        /// <summary>
        /// count of unsuccessful attempts left(for user PIN)
        /// if field equal 0 - that means that PIN is blocked
        /// </summary>
        public uint UserRetryCountLeft;

        /// <summary>
        /// Maximum length in bytes of the admin PIN
        /// </summary>
        public uint MaxAdminLen;

        /// <summary>
        /// Minimum length in bytes of the admin PIN
        /// </summary>
        public uint MinAdminPinLen;

        /// <summary>
        /// Maximum length in bytes of the user PIN
        /// </summary>
        public uint MaxUserPinLen;

        /// <summary>
        /// Minimum length in bytes of the user PIN
        /// </summary>
        public uint MinUserPinLen;

        /// <summary>
        /// The total amount of memory on the token in bytes in which public objects may be stored
        /// </summary>
        public uint TotalMemory;

        /// <summary>
        /// The amount of free (unused) memory on the token in bytes for public objects
        /// </summary>
        public uint FreeMemory;

        /// <summary>
        /// ATR
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] ATR;

        /// <summary>
        /// size of ATR
        /// </summary>
        public uint ATRLen;

        /// <summary>
        /// Class of token
        /// </summary>
        public uint TokenClass;

        /// <summary>
        /// Battery Voltage 
        /// </summary>
        public uint BatteryVoltage;

        /// <summary>
        /// Body color of the token  
        /// </summary>
        public uint BodyColor;

        /// <summary>
        /// Checksum of token firmware
        /// </summary>
        public uint ulFirmwareChecksum;

    }
}
