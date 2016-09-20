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

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;

namespace Net.Pkcs11Interop.Tests.HighLevelAPI
{
    /// <summary>
    /// DeriveKey tests.
    /// </summary>
    [TestClass]
    public class _25_DeriveKeyTest
    {
        /// <summary>
        /// DeriveKey test.
        /// </summary>
        /*[TestMethod]
        public void _01_BasicDeriveKeyTest()
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
                    ObjectHandle privateKey = null;
                    ObjectHandle publicKey = null;
                    Helpers.GenerateKeyPair(session, out publicKey, out privateKey);

                    //Copy public key data to CK_GOST3410_DERIVE_PARAMS
                    List<CKA> attributes = new List<CKA>();
                    attributes.Add(CKA.CKA_VALUE);
                    List<ObjectAttribute> objectAttributes = session.GetAttributeValue(publicKey, attributes);
                    byte[] data = new byte[64];
                    for (int i = 0; i < 64; i++)
                        data[i] = 0;
                    data = objectAttributes[0].GetValueAsByteArray();


                    byte[] ukm = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

                    // Specify mechanism parameters
                    CkGOST3410DeriveParams mechanismParams = new CkGOST3410DeriveParams(ukm, data);

                    // Specify derivation mechanism with parameters
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOSTR3410_DERIVE,mechanismParams);
                    

                    objectAttributes = new List<ObjectAttribute>();
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, false));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, false));
                   
                    // Derive key
                    ObjectHandle derivedKey = session.DeriveKey(mechanism, privateKey, objectAttributes);

                    // Do something interesting with derived key
                    //Assert.IsTrue(derivedKey.ObjectId != CK.CK_INVALID_HANDLE);

                    //session.DestroyObject(baseKey);
                    //session.DestroyObject(derivedKey);
                    session.Logout();
                }
            }
        }*/
    }
}

