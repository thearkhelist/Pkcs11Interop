﻿/*
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
using System.Runtime.InteropServices;

namespace Net.Pkcs11Interop.LowLevelAPI41.MechanismParams
{
    /// <summary>
    /// Provides the parameters for the CKM_CONCATENATE_BASE_AND_DATA, CKM_CONCATENATE_DATA_AND_BASE and CKM_XOR_BASE_AND_DATA mechanisms
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_GOST3410_DERIVE_PARAMS
    {
        /// <summary>
        /// identifier of the key derivation function
        /// </summary>
        public UInt32 kdf;

        /// <summary>
        /// pointer to data with public key of a receiver
        /// </summary>
        public IntPtr pPublicData;

        /// <summary>
        /// length of data with public key of a receiver (must be 64)
        /// </summary>
        public UInt32 ulPublicDataLen;

        /// <summary>
        /// pointer to a UKM data
        /// </summary>
        public IntPtr pUKM;
        
        /// <summary>
        /// length of UKM data in bytes (must be 8)
        /// </summary>
        public UInt32 ulUkmLen;




    }
}
