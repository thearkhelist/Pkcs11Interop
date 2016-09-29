using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Collections.Generic;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Net.Pkcs11Interop.Tests;
using Net.Pkcs11Interop.Common;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class KM_GOSTR3410_512_KEY_PAIR_GEN_Tests
    {
        [TestMethod]
        public void _01_GenerateKeyPairTest()
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

                    /* Набор параметров КриптоПро A алгоритма ГОСТ Р 34.10-2012(512) */
                    byte[] GOST3410_2012_512_params_oid = { 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01 };

                    /* Набор параметров КриптоПро алгоритма ГОСТ Р 34.11-2012(512) */
                    byte[] GOST3411_2012_512_params_oid = { 0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03 };

                    // Prepare attribute template of new public key
                    List<ObjectAttribute> publicKeyAttributes = new List<ObjectAttribute>();
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOSTR3410_512));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_GOSTR3410PARAMS, GOST3410_2012_512_params_oid));

                    // Prepare attribute template of new private key
                    List<ObjectAttribute> privateKeyAttributes = new List<ObjectAttribute>();
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOSTR3410_512));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_GOSTR3410PARAMS, GOST3410_2012_512_params_oid));
                    privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_GOSTR3411PARAMS, GOST3411_2012_512_params_oid));
                    
                    // Specify key generation mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

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
