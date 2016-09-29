using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Tests;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using System.Collections.Generic;
using System.IO;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class CKM_GOST28147_Tests
    {
        [TestMethod]
        public void _01_EncryptAndDecryptSinglePartTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RW session
                using (Session session = slot.OpenSession(false))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Generate symetric key
                    ObjectHandle generatedKey = Helpers.GenerateKey(session);

                    // Generate random initialization vector
                    byte[] iv = session.GenerateRandom(8);

                    // Specify encryption mechanism with initialization vector as parameter
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147, iv);

                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Our new password");

                    // Encrypt data
                    byte[] encryptedData = session.Encrypt(mechanism, generatedKey, sourceData);

                    // Do something interesting with encrypted data

                    // Decrypt data
                    byte[] decryptedData = session.Decrypt(mechanism, generatedKey, encryptedData);

                    // Do something interesting with decrypted data
                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);
                    session.Logout();
                }
            }
        }

        [TestMethod]
        public void _02_EncryptAndDecryptMultiPartTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RW session
                using (Session session = slot.OpenSession(false))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Generate symetric key
                    ObjectHandle generatedKey = Helpers.GenerateKey(session);

                    // Generate random initialization vector
                    byte[] iv = session.GenerateRandom(8);

                    // Specify encryption mechanism with initialization vector as parameter
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147, iv);

                    int bufferLength = 32;
                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Our new password is 12345678");
                    byte[] encryptedData = null;
                    byte[] decryptedData = null;

                    if (sourceData.Length <= bufferLength)
                    {
                        encryptedData = session.Encrypt(mechanism, generatedKey, sourceData);
                    }
                    else
                    {

                        // Multipart encryption can be used i.e. for encryption of streamed data
                        using (MemoryStream inputStream = new MemoryStream(sourceData), outputStream = new MemoryStream())
                        {
                            // Encrypt data
                            // Note that in real world application we would rather use bigger read buffer i.e. 4096
                            session.Encrypt(mechanism, generatedKey, inputStream, outputStream, bufferLength);

                            // Read whole output stream to the byte array so we can compare results more easily
                            encryptedData = outputStream.ToArray();
                        }
                    }


                    // Do something interesting with encrypted data
                    if (encryptedData.Length <= bufferLength)
                    {
                        decryptedData = session.Decrypt(mechanism, generatedKey, encryptedData);
                    }
                    else
                    {
                        // Multipart decryption can be used i.e. for decryption of streamed data
                        using (MemoryStream inputStream = new MemoryStream(encryptedData), outputStream = new MemoryStream())
                        {
                            // Decrypt data
                            // Note that in real world application we would rather use bigger read buffer i.e. 4096
                            session.Decrypt(mechanism, generatedKey, inputStream, outputStream, bufferLength);

                            // Read whole output stream to the byte array so we can compare results more easily
                            decryptedData = outputStream.ToArray();
                        }
                    }
                    // Do something interesting with decrypted data
                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);
                    session.Logout();
                }
            }
        }
    }
}