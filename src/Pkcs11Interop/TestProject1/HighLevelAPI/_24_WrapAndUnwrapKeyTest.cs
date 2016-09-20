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
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;

namespace Net.Pkcs11Interop.Tests.HighLevelAPI
{
    /// <summary>
    /// WrapKey and UnwrapKey tests.
    /// </summary>
    [TestClass]
    public class _24_WrapAndUnwrapKeyTest
    {
        /// <summary>
        /// Basic WrapKey and UnwrapKey test.
        /// </summary>
        /*[TestMethod]
        public void _01_BasicWrapAndUnwrapKeyTest()
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
                    
                    // Generate asymetric key pair
                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
                    //Helpers.GenerateKeyPair(session, out publicKey, out privateKey);

                    
                        byte[] ckaId = session.GenerateRandom(20);
                        byte[] GOST28147_params_oid = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };                    // Prepare attribute template of new key
                        List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_GOST28147PARAMS, GOST28147_params_oid));

                        // Specify key generation mechanism
                        Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147_KEY_GEN);

                        // Generate key
                        ObjectHandle secretKey =  session.GenerateKey(mechanism, objectAttributes);
                    ObjectHandle key = session.GenerateKey(mechanism, objectAttributes);
                        
                    

                    byte[] data = session.GenerateRandom(24);
                    byte[] ukm = session.GenerateRandom(8);

                    //CkGOST3410KeyWrapParams mechanismParams = new CkGOST3410KeyWrapParams(publicKey, ukm, data);

                    // Specify wrapping mechanism
                    mechanism = new Mechanism(CKM.CKM_GOST28147_KEY_WRAP,ukm);
                    
                    // Wrap key
                    byte[] wrappedKey = session.WrapKey(mechanism, key, secretKey);

                    // Do something interesting with wrapped key
                    Assert.IsNotNull(wrappedKey);

                    // Define attributes for unwrapped key
                    objectAttributes = new List<ObjectAttribute>();
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_DERIVE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));

                    // Unwrap key
                    ObjectHandle unwrappedKey = session.UnwrapKey(mechanism, privateKey, wrappedKey, objectAttributes);

                    // Do something interesting with unwrapped key
                    Assert.IsTrue(unwrappedKey.ObjectId != CK.CK_INVALID_HANDLE);

                    session.DestroyObject(privateKey);
                    session.DestroyObject(publicKey);
                    session.DestroyObject(secretKey);
                    session.Logout();
                }
            }
        }*/
    }
}

