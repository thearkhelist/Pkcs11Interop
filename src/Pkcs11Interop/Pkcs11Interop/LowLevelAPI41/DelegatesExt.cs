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
using Net.Pkcs11Interop.Common;

namespace Net.Pkcs11Interop.LowLevelAPI41
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_GetFunctionListExtendedDelegate(out IntPtr functionList);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_InitTokenDelegate(uint slotId, byte[] pin, uint pinLen, ref CK_RUTOKEN_INIT_PARAM initInfo);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_GetTokenInfoExtendedDelegate(uint slotId, ref CK_TOKEN_INFO_EXTENDED info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_UnblockUserPINDelegate(uint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_SetTokenNameDelegate(uint session, byte[] tokenName, uint tokenNameLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_SetLicenseDelegate(uint session, uint licenseNume, byte[] license, uint licenseLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_GetLicenseDelegate(uint session, uint licenseNume, byte[] license, ref uint licenseLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_GetCertificateInfoTextDelegate(uint session, uint cert, ref byte[] info, ref uint infoLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_PKCS7SignDelegate(uint session, byte[] data, uint dataLen, uint cert, byte[] envelope, uint envelopeLen, uint privKet, uint[] certificates, uint certificatesLen, uint flags);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_CreateCSRDelegate(uint session, uint publicKey, byte[] dn, uint dnLength, byte[] csr, uint csrLength, uint privKet, byte[] attributes, uint attributesLen, byte[] extensions, uint extensionsLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_FreeBufferDelegate(byte[] buffer);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_GetTokenNameDelegate(uint session, byte[] tokenName, ref uint tokenNameLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate uint C_EX_SetLocalPINDelegate(uint slotId, byte[] userPin, uint userPinLen, byte[] newLocalPin, uint newLocalPinLen, uint localID);
    




    /// <summary>
    /// Holds delegates for all PKCS#11 extention functions
    /// </summary>
    internal class DelegatesExt
    {
        /// <summary>
        /// Delegate for C_EX_GetFunctionListExtended
        /// </summary>
        internal C_EX_GetFunctionListExtendedDelegate C_EX_GetFunctionListExtended = null;

        /// <summary>
        /// Delegate for C_EX_InitToken
        /// </summary>
        internal C_EX_InitTokenDelegate C_EX_InitToken = null;

        /// <summary>
        /// Delegate for C_EX_GetTokenInfoExtended
        /// </summary>
        internal C_EX_GetTokenInfoExtendedDelegate C_EX_GetTokenInfoExtended = null;

        /// <summary>
        /// Delegate for C_EX_UnblockUserPIN
        /// </summary>
        internal C_EX_UnblockUserPINDelegate C_EX_UnblockUserPIN = null;

        /// <summary>
        /// Delegate for C_EX_SetTokenName
        /// </summary>
        internal C_EX_SetTokenNameDelegate C_EX_SetTokenName = null;

        /// <summary>
        /// Delegate for C_EX_SetLicense
        /// </summary>
        internal C_EX_SetLicenseDelegate C_EX_SetLicense = null;

        /// <summary>
        /// Delegate for C_EX_GetLicense
        /// </summary>
        internal C_EX_GetLicenseDelegate C_EX_GetLicense = null;

        /// <summary>
        /// Delegate for C_EX_GetCertificateInfoText
        /// </summary>
        internal C_EX_GetCertificateInfoTextDelegate C_EX_GetCertificateInfoText = null;

        /// <summary>
        /// Delegate for C_EX_GetTokenName
        /// </summary>
        internal C_EX_PKCS7SignDelegate C_EX_PKCS7Sign = null;

        /// <summary>
        /// Delegate for C_EX_CreateCSR
        /// </summary>
        internal C_EX_CreateCSRDelegate C_EX_CreateCSR = null;

        /// <summary>
        /// Delegate for C_EX_FreeBuffer
        /// </summary>
        internal C_EX_FreeBufferDelegate C_EX_FreeBuffer = null;

        /// <summary>
        /// Delegate for C_EX_GetTokenName
        /// </summary>
        internal C_EX_GetTokenNameDelegate C_EX_GetTokenName = null;

        /// <summary>
        /// Delegate for C_EX_SetLocalPIN
        /// </summary>
        internal C_EX_SetLocalPINDelegate C_EX_SetLocalPIN = null;

        /// <summary>
        /// Initializes new instance of Delegates class
        /// </summary>
        /// <param name="libraryHandle">Handle to the PKCS#11 library</param>
        /// <param name="useGetFunctionList">Flag indicating whether cryptoki function pointers should be acquired via C_GetFunctionList (true) or via platform native function (false)</param>
        internal DelegatesExt(IntPtr libraryHandle, bool useGetFunctionList)
        {
            if (useGetFunctionList)
            {
                if (libraryHandle != IntPtr.Zero)
                {
                    InitializeWithGetFunctionList(libraryHandle);
                }
                else
                {
                    InitializeWithGetFunctionList();
                }
            }
            else
            {
                if (libraryHandle != IntPtr.Zero)
                {
                    //InitializeWithoutGetFunctionList(libraryHandle);
                }
                else
                {
                    InitializeWithoutGetFunctionList();
                }
            }
        }

        /// <summary>
        /// Get delegates with C_GetFunctionList function from the dynamically loaded shared PKCS#11 library
        /// </summary>
        /// <param name="libraryHandle">Handle to the PKCS#11 library</param>
        private void InitializeWithGetFunctionList(IntPtr libraryHandle)
        {
            IntPtr cGetFunctionListPtr = UnmanagedLibrary.GetFunctionPointer(libraryHandle, "C_EX_GetFunctionListExtended");
            C_EX_GetFunctionListExtendedDelegate cGetFunctionList = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_GetFunctionListExtendedDelegate>(cGetFunctionListPtr);

            IntPtr functionList = IntPtr.Zero;

            CKR rv = (CKR)cGetFunctionList(out functionList);
            if ((rv != CKR.CKR_OK) || (functionList == IntPtr.Zero))
                throw new Pkcs11Exception("C_GetFunctionList", rv);

            CK_FUNCTION_LIST_EXTENDED ckFunctionList = (CK_FUNCTION_LIST_EXTENDED)UnmanagedMemory.Read(functionList, typeof(CK_FUNCTION_LIST_EXTENDED));
            Initialize(ckFunctionList);
        }

        /// <summary>
        /// Get delegates with C_GetFunctionList function from the statically linked PKCS#11 library
        /// </summary>
        private void InitializeWithGetFunctionList()
        {
            IntPtr functionList = IntPtr.Zero;

            CKR rv = (CKR)NativeMethods.C_EX_GetFunctionListExtended(out functionList);
            if ((rv != CKR.CKR_OK) || (functionList == IntPtr.Zero))
                throw new Pkcs11Exception("C_GetFunctionList", rv);

            CK_FUNCTION_LIST_EXTENDED ckFunctionList = (CK_FUNCTION_LIST_EXTENDED)UnmanagedMemory.Read(functionList, typeof(CK_FUNCTION_LIST_EXTENDED));
            Initialize(ckFunctionList);
        }

        /*/// <summary>
        /// Get delegates without C_GetFunctionList function from the dynamically loaded shared PKCS#11 library
        /// </summary>
        /// <param name="libraryHandle">Handle to the PKCS#11 library</param>
        private void InitializeWithoutGetFunctionList(IntPtr libraryHandle)
        {
            CK_FUNCTION_LIST_EXTENDED ckFunctionList = new CK_FUNCTION_LIST_EXTENDED();
            
            ckFunctionList.C_WaitForSlotEvent = UnmanagedLibrary.GetFunctionPointer(libraryHandle, "C_WaitForSlotEvent");

            Initialize(ckFunctionList);
        }*/

        /// <summary>
        /// Get delegates without C_GetFunctionList function from the statically linked PKCS#11 library
        /// </summary>
        private void InitializeWithoutGetFunctionList()
        {
            C_EX_GetFunctionListExtended = NativeMethods.C_EX_GetFunctionListExtended;
            C_EX_InitToken = NativeMethods.C_EX_InitToken;
            C_EX_GetTokenInfoExtended = NativeMethods.C_EX_GetTokenInfoExtended;           
            C_EX_UnblockUserPIN = NativeMethods.C_EX_UnblockUserPIN;
            C_EX_SetTokenName = NativeMethods.C_EX_SetTokenName;
            C_EX_SetLicense = NativeMethods.C_EX_SetLicense;
            C_EX_GetLicense = NativeMethods.C_EX_GetLicense;
            C_EX_GetCertificateInfoText = NativeMethods.C_EX_GetCertificateInfoText;
            C_EX_PKCS7Sign = NativeMethods.C_EX_PKCS7Sign;
            C_EX_CreateCSR = NativeMethods.C_EX_CreateCSR;
            C_EX_FreeBuffer = NativeMethods.C_EX_FreeBuffer;
            C_EX_GetTokenName = NativeMethods.C_EX_GetTokenName;
            C_EX_SetLocalPIN = NativeMethods.C_EX_SetLocalPIN;


        }

        /// <summary>
        /// Get delegates from unmanaged function pointers
        /// </summary>
        /// <param name="ckFunctionList">Structure which contains cryptoki function pointers</param>
        private void Initialize(CK_FUNCTION_LIST_EXTENDED ckFunctionList)
        {
            C_EX_GetFunctionListExtended = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_GetFunctionListExtendedDelegate>(ckFunctionList.C_EX_GetFunctionListExtended);
            C_EX_InitToken = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_InitTokenDelegate>(ckFunctionList.C_EX_InitToken);
            C_EX_GetTokenInfoExtended = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_GetTokenInfoExtendedDelegate>(ckFunctionList.C_EX_GetTokenInfoExtended);       
            C_EX_UnblockUserPIN = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_UnblockUserPINDelegate>(ckFunctionList.C_EX_UnblockUserPIN);
            C_EX_SetTokenName = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_SetTokenNameDelegate>(ckFunctionList.C_EX_SetTokenName);
            C_EX_SetLicense = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_SetLicenseDelegate>(ckFunctionList.C_EX_SetLicense);
            C_EX_GetLicense = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_GetLicenseDelegate>(ckFunctionList.C_EX_GetLicense);
            C_EX_GetCertificateInfoText = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_GetCertificateInfoTextDelegate>(ckFunctionList.C_EX_GetCertificateInfoText);
            C_EX_PKCS7Sign = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_PKCS7SignDelegate>(ckFunctionList.C_EX_PKCS7Sign);
            C_EX_CreateCSR = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_CreateCSRDelegate>(ckFunctionList.C_EX_CreateCSR);
            C_EX_FreeBuffer = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_FreeBufferDelegate>(ckFunctionList.C_EX_FreeBuffer);
            C_EX_GetTokenName = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_GetTokenNameDelegate>(ckFunctionList.C_EX_GetTokenName);
            C_EX_SetLocalPIN = UnmanagedLibrary.GetDelegateForFunctionPointer<C_EX_SetLocalPINDelegate>(ckFunctionList.C_EX_SetLocalPIN);            
        }
    }
}
