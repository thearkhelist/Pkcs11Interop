/*
 *  Pkcs11Interop - Open-source .NET wrapper for unmanaged PKCS#11 libraries
 *  Copyright (C) 2012 Jaroslav Imrich <jimrich(at)jimrich(dot)sk>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  If this license does not suit your needs you can purchase a commercial
 *  license from Pkcs11Interop author.
 */

using NUnit.Framework;
using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI;
using System.Text;
using System.IO;
using Net.Pkcs11Interop.LowLevelAPI.MechanismParams;

namespace Net.Pkcs11Interop.Tests.LowLevelAPI
{
    /// <summary>
    /// C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinish, C_DecryptInit, C_Decrypt, C_DecryptUpdate and C_DecryptFinish tests.
    /// </summary>
    [TestFixture()]
    public class EncryptAndDecryptTest
    {
        /// <summary>
        /// C_EncryptInit, C_Encrypt, C_DecryptInit and C_Decrypt test.
        /// </summary>
        [Test()]
        public void EncryptAndDecryptSinglePartTest()
        {
            CKR rv = CKR.CKR_OK;
            
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(null);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());
                
                // Find first slot with token present
                uint slotId = Helpers.GetUsableSlot(pkcs11);
                
                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Login as normal user
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, (uint)Settings.NormalUserPinArray.Length);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Generate symetric key
                uint keyId = CK.CK_INVALID_HANDLE;
                rv = Helpers.GenerateKey(pkcs11, session, ref keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Generate random initialization vector
                byte[] iv = new byte[8];
                rv = pkcs11.C_GenerateRandom(session, iv, (uint)iv.Length);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Specify encryption mechanism with initialization vector as parameter.
                // Note that CkmUtils.CreateMechanism() automaticaly copies iv into newly allocated unmanaged memory.
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_DES3_CBC, iv);
                
                // Initialize encryption operation
                rv = pkcs11.C_EncryptInit(session, ref mechanism, keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData = ConvertUtils.Utf8StringToBytes("Our new password");

                // Get length of encrypted data in first call
                uint encryptedDataLen = 0;
                rv = pkcs11.C_Encrypt(session, sourceData, (uint)sourceData.Length, null, ref encryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(encryptedDataLen > 0);

                // Allocate array for encrypted data
                byte[] encryptedData = new byte[encryptedDataLen];

                // Get encrypted data in second call
                rv = pkcs11.C_Encrypt(session, sourceData, (uint)sourceData.Length, encryptedData, ref encryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Do something interesting with encrypted data

                // Initialize decryption operation
                rv = pkcs11.C_DecryptInit(session, ref mechanism, keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Get length of decrypted data in first call
                uint decryptedDataLen = 0;
                rv = pkcs11.C_Decrypt(session, encryptedData, (uint)encryptedData.Length, null, ref decryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(decryptedDataLen > 0);
                
                // Allocate array for decrypted data
                byte[] decryptedData = new byte[decryptedDataLen];

                // Get decrypted data in second call
                rv = pkcs11.C_Decrypt(session, encryptedData, (uint)encryptedData.Length, decryptedData, ref decryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Do something interesting with decrypted data
                Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                // In LowLevelAPI we have to free unmanaged memory taken by mechanism parameter (iv in this case)
                UnmanagedMemory.Free(ref mechanism.Parameter);
                mechanism.ParameterLen = 0;

                rv = pkcs11.C_DestroyObject(session, keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_Logout(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// C_EncryptInit, C_EncryptUpdate, C_EncryptFinish, C_DecryptInit, C_DecryptUpdate and C_DecryptFinish test.
        /// </summary>
        [Test()]
        public void EncryptAndDecryptMultiPartTest()
        {
            CKR rv = CKR.CKR_OK;
            
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(null);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());
                
                // Find first slot with token present
                uint slotId = Helpers.GetUsableSlot(pkcs11);
                
                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Login as normal user
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, (uint)Settings.NormalUserPinArray.Length);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Generate symetric key
                uint keyId = CK.CK_INVALID_HANDLE;
                rv = Helpers.GenerateKey(pkcs11, session, ref keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Generate random initialization vector
                byte[] iv = new byte[8];
                rv = pkcs11.C_GenerateRandom(session, iv, (uint)iv.Length);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Specify encryption mechanism with initialization vector as parameter.
                // Note that CkmUtils.CreateMechanism() automaticaly copies iv into newly allocated unmanaged memory.
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_DES3_CBC, iv);
                
                byte[] sourceData = ConvertUtils.Utf8StringToBytes("Our new password");
                byte[] encryptedData = null;
                byte[] decryptedData = null;

                // Multipart encryption functions C_EncryptUpdate and C_EncryptFinal can be used i.e. for encryption of streamed data
                using (MemoryStream inputStream = new MemoryStream(sourceData), outputStream = new MemoryStream())
                {
                    // Initialize encryption operation
                    rv = pkcs11.C_EncryptInit(session, ref mechanism, keyId);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Prepare buffer for source data part
                    // Note that in real world application we would rather use bigger buffer i.e. 4096 bytes long
                    byte[] part = new byte[8];

                    // Prepare buffer for encrypted data part
                    // Note that in real world application we would rather use bigger buffer i.e. 4096 bytes long
                    byte[] encryptedPart = new byte[8];
                    uint encryptedPartLen = (uint)encryptedPart.Length;

                    // Read input stream with source data
                    int bytesRead = 0;
                    while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
                    {
                        // Encrypt each individual source data part
                        encryptedPartLen = (uint)encryptedPart.Length;
                        rv = pkcs11.C_EncryptUpdate(session, part, (uint)bytesRead, encryptedPart, ref encryptedPartLen);
                        if (rv != CKR.CKR_OK)
                            Assert.Fail(rv.ToString());

                        // Append encrypted data part to the output stream
                        outputStream.Write(encryptedPart, 0, (int)encryptedPartLen);
                    }

                    // Get the length of last encrypted data part in first call
                    byte[] lastEncryptedPart = null;
                    uint lastEncryptedPartLen = 0;
                    rv = pkcs11.C_EncryptFinal(session, null, ref lastEncryptedPartLen);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());
                    
                    // Allocate array for the last encrypted data part
                    lastEncryptedPart = new byte[lastEncryptedPartLen];

                    // Get the last encrypted data part in second call
                    rv = pkcs11.C_EncryptFinal(session, lastEncryptedPart, ref lastEncryptedPartLen);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Append the last encrypted data part to the output stream
                    outputStream.Write(lastEncryptedPart, 0, (int)lastEncryptedPartLen);

                    // Read whole output stream to the byte array so we can compare results more easily
                    encryptedData = outputStream.ToArray();
                }

                // Do something interesting with encrypted data

                // Multipart decryption functions C_DecryptUpdate and C_DecryptFinal can be used i.e. for decryption of streamed data
                using (MemoryStream inputStream = new MemoryStream(encryptedData), outputStream = new MemoryStream())
                {
                    // Initialize decryption operation
                    rv = pkcs11.C_DecryptInit(session, ref mechanism, keyId);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Prepare buffer for encrypted data part
                    // Note that in real world application we would rather use bigger buffer i.e. 4096 bytes long
                    byte[] encryptedPart = new byte[8];

                    // Prepare buffer for decrypted data part
                    // Note that in real world application we would rather use bigger buffer i.e. 4096 bytes long
                    byte[] part = new byte[8];
                    uint partLen = (uint)part.Length;

                    // Read input stream with encrypted data
                    int bytesRead = 0;
                    while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
                    {
                        // Decrypt each individual encrypted data part
                        partLen = (uint)part.Length;
                        rv = pkcs11.C_DecryptUpdate(session, encryptedPart, (uint)bytesRead, part, ref partLen);
                        if (rv != CKR.CKR_OK)
                            Assert.Fail(rv.ToString());

                        // Append decrypted data part to the output stream
                        outputStream.Write(part, 0, (int)partLen);
                    }

                    // Get the length of last decrypted data part in first call
                    byte[] lastPart = null;
                    uint lastPartLen = 0;
                    rv = pkcs11.C_DecryptFinal(session, null, ref lastPartLen);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Allocate array for the last decrypted data part
                    lastPart = new byte[lastPartLen];

                    // Get the last decrypted data part in second call
                    rv = pkcs11.C_DecryptFinal(session, lastPart, ref lastPartLen);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Append the last decrypted data part to the output stream
                    outputStream.Write(lastPart, 0, (int)lastPartLen);

                    // Read whole output stream to the byte array so we can compare results more easily
                    decryptedData = outputStream.ToArray();
                }

                // Do something interesting with decrypted data
                Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                // In LowLevelAPI we have to free unmanaged memory taken by mechanism parameter (iv in this case)
                UnmanagedMemory.Free(ref mechanism.Parameter);
                mechanism.ParameterLen = 0;
                
                rv = pkcs11.C_DestroyObject(session, keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_Logout(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
        
        /// <summary>
        /// C_EncryptInit, C_Encrypt, C_DecryptInit and C_Decrypt test with CKM_RSA_PKCS_OAEP mechanism.
        /// </summary>
        [Test()]
        public void EncryptAndDecryptSinglePartOaepTest()
        {
            CKR rv = CKR.CKR_OK;
            
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(null);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());
                
                // Find first slot with token present
                uint slotId = Helpers.GetUsableSlot(pkcs11);
                
                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Login as normal user
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, (uint)Settings.NormalUserPinArray.Length);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Generate asymetric key pair
                uint pubKeyId = CK.CK_INVALID_HANDLE;
                uint privKeyId = CK.CK_INVALID_HANDLE;
                rv = Helpers.GenerateKeyPair(pkcs11, session, ref pubKeyId, ref privKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Specify mechanism parameters
                CK_RSA_PKCS_OAEP_PARAMS mechanismParams = new CK_RSA_PKCS_OAEP_PARAMS();
                mechanismParams.HashAlg = (uint)CKM.CKM_SHA_1;
                mechanismParams.Mgf = (uint)CKG.CKG_MGF1_SHA1;
                mechanismParams.Source = 0;
                mechanismParams.SourceData = IntPtr.Zero;
                mechanismParams.SourceDataLen = 0;
                
                // Specify encryption mechanism with parameters
                // Note that CkmUtils.CreateMechanism() automaticaly copies mechanismParams into newly allocated unmanaged memory.
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_RSA_PKCS_OAEP, mechanismParams);
                
                // Initialize encryption operation
                rv = pkcs11.C_EncryptInit(session, ref mechanism, pubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");
                
                // Get length of encrypted data in first call
                uint encryptedDataLen = 0;
                rv = pkcs11.C_Encrypt(session, sourceData, (uint)sourceData.Length, null, ref encryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                Assert.IsTrue(encryptedDataLen > 0);
                
                // Allocate array for encrypted data
                byte[] encryptedData = new byte[encryptedDataLen];
                
                // Get encrypted data in second call
                rv = pkcs11.C_Encrypt(session, sourceData, (uint)sourceData.Length, encryptedData, ref encryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Do something interesting with encrypted data
                
                // Initialize decryption operation
                rv = pkcs11.C_DecryptInit(session, ref mechanism, privKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Get length of decrypted data in first call
                uint decryptedDataLen = 0;
                rv = pkcs11.C_Decrypt(session, encryptedData, (uint)encryptedData.Length, null, ref decryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                Assert.IsTrue(decryptedDataLen > 0);
                
                // Allocate array for decrypted data
                byte[] decryptedData = new byte[decryptedDataLen];
                
                // Get decrypted data in second call
                rv = pkcs11.C_Decrypt(session, encryptedData, (uint)encryptedData.Length, decryptedData, ref decryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Array may need to be shrinked
                if (decryptedData.Length != decryptedDataLen)
                    Array.Resize(ref decryptedData, (int)decryptedDataLen);

                // Do something interesting with decrypted data
                Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                // In LowLevelAPI we have to free unmanaged memory taken by mechanism parameter
                UnmanagedMemory.Free(ref mechanism.Parameter);
                mechanism.ParameterLen = 0;
                
                rv = pkcs11.C_DestroyObject(session, privKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_DestroyObject(session, pubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_Logout(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
    }
}
