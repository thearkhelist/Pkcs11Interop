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
    public static class TOKEN_TYPE
    {
        /// <summary>
        ///TOKEN_TYPE_UNKNOWN
        /// </summary>
        public const uint TOKEN_TYPE_UNKNOWN = 0xFF;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_ECP
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_ECP = 0x01;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_LITE
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_LITE = 0x02;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN      =          0x03;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_PINPAD_FAMILY
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_PINPAD_FAMILY = 0x04;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_ECPDUAL_USB
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_ECPDUAL_USB =   0x09;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_KAZTOKEN
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_KAZTOKEN   =    0x11;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_ECPDUAL_BT
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_ECPDUAL_BT  =   0x69;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_ECPDUAL_UART
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_ECPDUAL_UART =  0xA9;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_WEB
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_WEB   =         0x23;

        /// <summary>
        ///TOKEN_TYPE_RUTOKEN_SC_JC
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_SC_JC      =    0x41;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_KAZTOKEN_SC_JC
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_KAZTOKEN_SC_JC = 0x51;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_LITE_SC_JC
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_LITE_SC_JC   =  0x42;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_LITE_SD
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_LITE_SD    =    0x82;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_ECP_SD
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_ECP_SD     =    0x81;

        /// <summary>
        /// TOKEN_TYPE_RUTOKEN_KAZTOKEN_SD
        /// </summary>
        public const uint TOKEN_TYPE_RUTOKEN_KAZTOKEN_SD   = 0x91;

    }
}
