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

namespace Net.Pkcs11Interop.Common
{
    /// <summary>
    /// Bit flags
    /// </summary>
    public static class TOKEN_FLAGS
    {

        /// <summary>
        ///TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN - if it is set, that means that administrator(SO) can change user PIN
        /// </summary>
        public const uint TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN    =     0x00000001;

        /// <summary>
        /// TOKEN_FLAGS_USER_CHANGE_USER_PIN - if it is set, that means that user can change user PIN
        /// </summary>
        public const uint TOKEN_FLAGS_USER_CHANGE_USER_PIN    =      0x00000002;

        /// <summary>
        /// TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT - if it is set, that means that current administrator(SO) PIN is not default
        /// </summary>
        public const uint TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT    =     0x00000004;

        /// <summary>
        /// TOKEN_FLAGS_USER_PIN_NOT_DEFAULT - if it is set, that means that current user PIN not default
        /// </summary>
        public const uint TOKEN_FLAGS_USER_PIN_NOT_DEFAULT  =        0x00000008;

        /// <summary>
        /// TOKEN_FLAGS_SUPPORT_FKN - if it is set, that means that token supports CryptoPro FKN
        /// </summary>
        public const uint TOKEN_FLAGS_SUPPORT_FKN = 0x00000010;

        /// <summary>
        /// TOKEN_FLAGS_SUPPORT_SM - if it is set, that means that token supports communication using Secure Messaging
        /// </summary>
        public const uint TOKEN_FLAGS_SUPPORT_SM             =       0x00000040;

        /// <summary>
        /// TOKEN_FLAGS_HAS_FLASH_DRIVE - if it is set, that means that token has Flash Drive
        /// </summary>
        public const uint TOKEN_FLAGS_HAS_FLASH_DRIVE = 0x00000080;

        /// <summary>
        /// TOKEN_FLAGS_CAN_CHANGE_SM_MODE - if it is set, that means that token can be formatted to support SM
        /// </summary>
        public const uint TOKEN_FLAGS_CAN_CHANGE_SM_MODE = 0x00000100;

        /// <summary>
        /// TOKEN_FLAGS_FW_CHECKSUM_INVALID - if it is set, that means that 'ulFirmwareChecksum' field contains different from the reference(stored at Token) firmware checksum
        /// </summary>
        public const uint TOKEN_FLAGS_FW_CHECKSUM_INVALID = 0x80000000;

        /// <summary>
        /// TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE - if it is set, that means Token does not support firmware checksum request and 'ulFirmwareChecksum' can not be used
        /// </summary>
        public const uint TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE = 0x40000000;
    }
}
