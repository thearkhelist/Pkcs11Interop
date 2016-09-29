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
using System.Runtime.InteropServices;

namespace Net.Pkcs11Interop.LowLevelAPI81
{
    /// <summary>
    /// Provides information about a token
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_RUTOKEN_INIT_PARAM
    {

        /// <summary>
        /// ulSizeofThisStructure
        /// </summary>
        public uint ulSizeofThisStructure;

        /// <summary>
        /// UseRepairMode
        /// </summary>
        public uint UseRepairMode;
        
        /// <summary>
        /// pNewAdminPin
        /// </summary>
        //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public IntPtr pNewAdminPin;

        /// <summary>
        /// ulNewAdminPinLen
        /// </summary>
        public uint ulNewAdminPinLen;

        /// <summary>
        /// pNewUserPin
        /// </summary>
        //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public IntPtr pNewUserPin;

        /// <summary>
        /// ulNewUserPinLen
        /// </summary>
        public uint ulNewUserPinLen;

        /// <summary>
        /// ChangeUserPINPolicy
        /// </summary>
        public uint ChangeUserPINPolicy;

        /// <summary>
        /// ulMinAdminPinLen
        /// </summary>
        public uint ulMinAdminPinLen;

        /// <summary>
        /// ulMinUserPinLen
        /// </summary>
        public uint ulMinUserPinLen;

        /// <summary>
        /// ulMaxAdminRetryCount
        /// </summary>
        public uint ulMaxAdminRetryCount;

        /// <summary>
        /// ulMaxUserRetryCount
        /// </summary>
        public uint ulMaxUserRetryCount;

        /// <summary>
        /// pTokenLabel
        /// </summary>
        //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public IntPtr pTokenLabel;

        /// <summary>
        /// ulLabelLen
        /// </summary>
        public uint ulLabelLen;
        
        /// <summary>
        /// ulSmMode
        /// </summary>
        public uint ulSmMode;

    }
}
