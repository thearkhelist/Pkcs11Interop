using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Net.Pkcs11Interop.Tests;
using System.Collections.Generic;
using System.IO;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class CKM_GOST28147_ECB_Tests
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
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147_ECB, iv);

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
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147_ECB, iv);

                    int bufferLength = 8;
                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("12345678");
                    byte[] encryptedData = null;
                    byte[] decryptedData = null;

                    // Multipart encryption can be used i.e. for encryption of streamed data
                    using (MemoryStream inputStream = new MemoryStream(sourceData), outputStream = new MemoryStream())
                    {
                        // Encrypt data
                        // Note that in real world application we would rather use bigger read buffer i.e. 4096
                        session.Encrypt(mechanism, generatedKey, inputStream, outputStream, bufferLength);

                        // Read whole output stream to the byte array so we can compare results more easily
                        encryptedData = outputStream.ToArray();
                    }

                    // Do something interesting with encrypted data

                    // Multipart decryption can be used i.e. for decryption of streamed data
                    using (MemoryStream inputStream = new MemoryStream(encryptedData), outputStream = new MemoryStream())
                    {
                        // Decrypt data
                        // Note that in real world application we would rather use bigger read buffer i.e. 4096
                        session.Decrypt(mechanism, generatedKey, inputStream, outputStream, bufferLength);

                        // Read whole output stream to the byte array so we can compare results more easily
                        decryptedData = outputStream.ToArray();
                    }

                    // Do something interesting with decrypted data
                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);
                    session.Logout();
                }
            }
        }


        /*[TestMethod]
        public void _03_BasicWrapAndUnwrapKeyTest()
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

                    byte[] param = session.GenerateRandom(8);
                    byte[] GOST28147_params_oid = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };                    // Prepare attribute template of new key
                    byte[] data = session.GenerateRandom(32);

                    List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, false));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, false));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_GOST28147PARAMS, GOST28147_params_oid));

                    Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147_KEY_GEN);
                    ObjectHandle tempKey = session.GenerateKey(mechanism, objectAttributes);
                    // Generate key

                    ObjectHandle key = Helpers.GenerateKey(session);
                    List<ObjectAttribute> changeObjectAttributes = new List<ObjectAttribute>();
                    changeObjectAttributes.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
                    session.SetAttributeValue(tempKey, changeObjectAttributes);
                    session.SetAttributeValue(key, changeObjectAttributes);

                    mechanism = new Mechanism(CKM.CKM_GOST28147_ECB);

                    // Wrap key
                    byte[] wrappedKey = session.WrapKey(mechanism, key, tempKey);

                    // Do something interesting with wrapped key
                    Assert.IsNotNull(wrappedKey);

                    // Define attributes for unwrapped key
                    objectAttributes = new List<ObjectAttribute>();
                    //objectAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));

                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, false));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, false));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_GOST28147PARAMS, GOST28147_params_oid));

                    // Unwrap key
                    ObjectHandle unwrappedKey = session.UnwrapKey(mechanism, key, wrappedKey, objectAttributes);

                    // Do something interesting with unwrapped key
                    Assert.IsTrue(unwrappedKey.ObjectId != CK.CK_INVALID_HANDLE);

                    session.DestroyObject(key);
                    session.DestroyObject(unwrappedKey);
                    session.DestroyObject(tempKey);
                    session.Logout();
                }
            }
        }*/
    }
}
