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

namespace Net.Pkcs11Interop.LowLevelAPI41
{
    /// <summary>
    /// Structure which contains a Cryptoki version and a function pointer to each function in the Cryptoki API
    /// </summary>
#if SILVERLIGHT
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    internal class CK_FUNCTION_LIST
#else
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    internal struct CK_FUNCTION_LIST_EXTENDED
#endif
    {
        /// <summary>
        /// Cryptoki version
        /// </summary>
        internal CK_VERSION version;

        /// <summary>
        /// Pointer to C_EX_GetFunctionListExtended
        /// </summary>
        internal IntPtr C_EX_GetFunctionListExtended;

        /// <summary>
        /// Pointer to C_EX_InitToken
        /// </summary>
        internal IntPtr C_EX_InitToken;

        /// <summary>
        /// Pointer to C_EX_GetTokenInfoExtended
        /// </summary>
        internal IntPtr C_EX_GetTokenInfoExtended; 

        /// <summary>
        /// Pointer to C_EX_UnblockUserPIN
        /// </summary>
        internal IntPtr C_EX_UnblockUserPIN;

        /// <summary>
        /// Pointer to C_EX_SetTokenName
        /// </summary>
        internal IntPtr C_EX_SetTokenName;

        /// <summary>
        /// Pointer to C_EX_GetTokenName
        /// </summary>
        internal IntPtr C_EX_GetTokenName;

        /// <summary>
        /// Pointer to C_EX_SetLicense
        /// </summary>
        internal IntPtr C_EX_SetLicense;

        /// <summary>
        /// Pointer to C_EX_GetLicense
        /// </summary>
        internal IntPtr C_EX_GetLicense;

        /// <summary>
        /// Pointer to C_EX_GetCertificateInfoText
        /// </summary>
        internal IntPtr C_EX_GetCertificateInfoText;

        /// <summary>
        /// Pointer to C_EX_PKCS7Sign
        /// </summary>
        internal IntPtr C_EX_PKCS7Sign;

        /// <summary>
        /// Pointer to C_EX_CreateCSR
        /// </summary>
        internal IntPtr C_EX_CreateCSR;

        /// <summary>
        /// Pointer to C_EX_FreeBuffer
        /// </summary>
        internal IntPtr C_EX_FreeBuffer;

        /// <summary>
        /// Pointer to C_EX_SetLocalPIN
        /// </summary>
        internal IntPtr C_EX_SetLocalPIN;

    }
}
