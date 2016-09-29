using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Tests;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using System.Collections.Generic;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class CKM_GOST28147_KEY_GEN_Tests
    {
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


                    byte[] ckaId = session.GenerateRandom(20);
                    byte[] GOST28147_params_oid = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };                    // Prepare attribute template of new key
                    List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                    objectAttributes.Add(new ObjectAttribute(CKA.CKA_GOST28147PARAMS, GOST28147_params_oid));

                    // Specify key generation mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147_KEY_GEN);

                    // Generate key
                    ObjectHandle objectHandle = session.GenerateKey(mechanism, objectAttributes);

                    // Do something interesting with generated key
                    ulong tmp = session.GetObjectSize(objectHandle);
                    // Destroy object
                    session.DestroyObject(objectHandle);

                    session.Logout();
                }
            }
        }
    }
}
