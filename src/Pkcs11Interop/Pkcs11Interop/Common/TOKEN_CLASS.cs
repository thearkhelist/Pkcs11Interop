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
    public static class TOKEN_CLASS
    {
        /// <summary>
        ///TOKEN_CLASS_UNKNOWN
        /// </summary>
        public const uint TOKEN_CLASS_UNKNOWN = 0xFF;

        /// <summary>
        ///TOKEN_CLASS_S
        /// </summary>
        public const uint TOKEN_CLASS_S = 0x00;

        /// <summary>
        ///TOKEN_CLASS_UNKNOWN
        /// </summary>
        public const uint TOKEN_CLASS_ECP = 0x01;

        /// <summary>
        ///TOKEN_CLASS_UNKNOWN
        /// </summary>
        public const uint TOKEN_CLASS_LITE = 0x02;

        /// <summary>
        ///TOKEN_CLASS_UNKNOWN
        /// </summary>
        public const uint TOKEN_CLASS_WEB = 0x03;

        /// <summary>
        ///TOKEN_CLASS_UNKNOWN
        /// </summary>
        public const uint TOKEN_CLASS_PINPAD = 0x04;

        /// <summary>
        ///TOKEN_CLASS_UNKNOWN
        /// </summary>
        public const uint TOKEN_CLASS_ECPDUAL = 0x09;

        /// <summary>
        ///TOKEN_CLASS_UNKNOWN
        /// </summary>
        public const uint TOKEN_CLASS_KAZTOKEN = 0x11;
    }
}
