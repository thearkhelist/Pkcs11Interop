using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.Tests;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class CKM_GOSTR3410_KEY_WRAP
    {
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

                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
                    Helpers.GenerateKeyPair(session, out publicKey, out privateKey);

                    
                    byte[] GOST28147_params_oid = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };                    // Prepare attribute template of new key
                    

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

                    //ObjectHandle key = Helpers.GenerateKey(session);
                    List<ObjectAttribute> changeObjectAttributes = new List<ObjectAttribute>();
                    changeObjectAttributes.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
                    session.SetAttributeValue(tempKey, changeObjectAttributes);
                    //session.SetAttributeValue(key, changeObjectAttributes);
                    List<CKA> attributes = new List<CKA>();
                    attributes.Add(CKA.CKA_VALUE);
                    List<ObjectAttribute> tempObjectAttributes = session.GetAttributeValue(tempKey, attributes);
                    byte[] data = new byte[64];
                    //for (int i = 0; i < 64; i++)
                    //    data[i] = 0;
                    data = tempObjectAttributes[0].GetValueAsByteArray();

                    byte[] ukm = session.GenerateRandom(8);

                    CkGOST3410KeyWrapParams parametrs = new CkGOST3410KeyWrapParams(publicKey, ukm, data);

                    mechanism = new Mechanism(CKM.CKM_GOSTR3410_KEY_WRAP, parametrs);

                    // Wrap key
                    byte[] wrappedKey = session.WrapKey(mechanism, publicKey, tempKey);

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
                    ObjectHandle unwrappedKey = session.UnwrapKey(mechanism, privateKey, wrappedKey, objectAttributes);

                    // Do something interesting with unwrapped key
                    Assert.IsTrue(unwrappedKey.ObjectId != CK.CK_INVALID_HANDLE);

                    session.DestroyObject(publicKey);
                    session.DestroyObject(privateKey);
                    session.DestroyObject(unwrappedKey);
                    session.DestroyObject(tempKey);
                    session.Logout();
                }
            }
        }*/
    }
}
