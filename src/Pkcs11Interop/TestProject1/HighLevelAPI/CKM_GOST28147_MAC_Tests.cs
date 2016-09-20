using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.Tests;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class CKM_GOST28147_MAC_Tests
    {
        [TestMethod]
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

                    // Generate key
                    ObjectHandle key = Helpers.GenerateKey(session);

                    // Specify signing mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147_MAC);

                    byte[] sourceData = session.GenerateRandom(64);

                    // Sign data
                    byte[] signature = session.Sign(mechanism, key, sourceData);

                    // Do something interesting with signature

                    // Verify signature
                    bool isValid = false;
                    session.Verify(mechanism, key, sourceData, signature, out isValid);

                    // Do something interesting with verification result
                    Assert.IsTrue(isValid);

                    session.DestroyObject(key);
                    session.Logout();
                }
            }
        }
    }
}
