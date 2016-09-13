<<<<<<< HEAD:src/Pkcs11Interop/TestProject1/HighLevelAPI/_31_GenerateKeyAndKeyPairTest_RSA.cs
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

using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Net.Pkcs11Interop.Tests.HighLevelAPI
{
    /// <summary>
    /// GenerateKey and GenerateKeyPair tests.
    /// </summary>
    [TestClass]
    public class _31_GenerateKeyAndKeyPairTest_RSA
    {
        /*
        /// <summary>
        /// GenerateKey test.
        /// </summary>
        [TestMethod]
        public void _01_GenerateKeyTest()
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

                    // Prepare attribute template of new key
                    List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_DES3));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));

                    // Specify key generation mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_DES3_KEY_GEN);

                    // Generate key
                    ObjectHandle objectHandle = session.GenerateKey(mechanism, objectAttributes);

                    // Do something interesting with generated key

                    // Destroy object
                    session.DestroyObject(objectHandle);
                    
                    session.Logout();
                }
            }
        }
        */

        public void _02_GenerateKeyPairTest()
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

                    // The CKA_ID attribute is intended as a means of distinguishing multiple key pairs held by the same subject
                    byte[] ckaId = session.GenerateRandom(20);

                    // Prepare attribute template of new public key
                    List<ObjectAttribute> publicKeyAttributes = new List<ObjectAttribute>();
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY_RECOVER, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS_BITS, 1024));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

                    // Prepare attribute template of new private key
                    List<ObjectAttribute> privateKeyAttributes = new List<ObjectAttribute>();
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN_RECOVER, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));

                    // Specify key generation mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

                    // Generate key pair
                    ObjectHandle publicKeyHandle = null;
                    ObjectHandle privateKeyHandle = null;
                    session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

                    // Do something interesting with generated key pair
                    
                    // Destroy keys
                    session.DestroyObject(privateKeyHandle);
                    session.DestroyObject(publicKeyHandle);

                    session.Logout();
                }
            }
        }
    }
}

=======
﻿

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using System;
using System.Collections.Generic;

namespace Net.Pkcs11Interop.Tests
{
    class Program
    {
        static void Main(string[] args)
        {
            _20_SignAndVerifyTest test2 = new _20_SignAndVerifyTest();
            //test2._01_SignAndVerifySinglePartTest();
            Testing test1 = new Testing();
            test1._01_GenerateKeyTest();
            //test1._02_GenerateKeyPairTest();
            Console.WriteLine("Success. Press anything to exit.");
            Console.ReadLine();

            
        }
    }
    class Testing
    {
        public void _01_GenerateKeyTest()
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

                    // Prepare attribute template of new key
                    List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));

                    // Specify key generation mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147_KEY_GEN);

                    // Generate key
                    ObjectHandle objectHandle = session.GenerateKey(mechanism, objectAttributes);

                    // Do something interesting with generated key

                    // Destroy object
                    session.DestroyObject(objectHandle);

                    session.Logout();
                }
            }
        }

        public void _02_GenerateKeyPairTest()
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

                    // The CKA_ID attribute is intended as a means of distinguishing multiple key pairs held by the same subject
                    byte[] ckaId = session.GenerateRandom(20);

                    // Prepare attribute template of new public key
                    List<ObjectAttribute> publicKeyAttributes = new List<ObjectAttribute>();
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY_RECOVER, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS_BITS, 1024));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

                    // Prepare attribute template of new private key
                    List<ObjectAttribute> privateKeyAttributes = new List<ObjectAttribute>();
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN_RECOVER, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));

                    // Specify key generation mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

                    // Generate key pair
                    ObjectHandle publicKeyHandle = null;
                    ObjectHandle privateKeyHandle = null;
                    session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

                    // Do something interesting with generated key pair

                    // Destroy keys
                    //session.DestroyObject(privateKeyHandle);
                    //session.DestroyObject(publicKeyHandle);

                    session.Logout();
                }
            }
        }
    }
    public class _20_SignAndVerifyTest
    {
        public void _01_SignAndVerifySinglePartTest()
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

                    // Specify signing mechanism
                    byte[] ckaId = session.GenerateRandom(20);

                    // Prepare attribute template of new public key
                    List<ObjectAttribute> publicKeyAttributes = new List<ObjectAttribute>();
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY_RECOVER, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS_BITS, 1024));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));

                    // Prepare attribute template of new private key
                    List<ObjectAttribute> privateKeyAttributes = new List<ObjectAttribute>();
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN_RECOVER, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));

                    // Specify key generation mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

                    // Generate key pair
                    ObjectHandle publicKeyHandle = null;
                    ObjectHandle privateKeyHandle = null;
                    session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");

                    // Sign data
                    byte[] signature = session.Sign(mechanism, privateKeyHandle, sourceData);

                    // Do something interesting with signature

                    // Verify signature
                    bool isValid = false;
                    session.Verify(mechanism, publicKeyHandle, sourceData, signature, out isValid);

                    // Do something interesting with verification result
                    if (isValid) {; }

                    session.DestroyObject(privateKeyHandle);
                    session.DestroyObject(publicKeyHandle);
                    session.Logout();
                }
            }
        }
    }
}
>>>>>>> origin/master:src/Pkcs11Interop/ConsoleApplication1/Program.cs
