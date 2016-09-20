using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Net.Pkcs11Interop.Tests;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using Net.Pkcs11Interop.LowLevelAPI40;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class CKM_GOST3410_DERIVE_Tests
    {
        [TestMethod]
        public void _01_BasicDeriveKeyTest()
        {
            using (Net.Pkcs11Interop.HighLevelAPI.Pkcs11 pkcs11 = new Net.Pkcs11Interop.HighLevelAPI.Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
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
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOSTR3410_DERIVE, mechanismParams);


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
        }
    }
}