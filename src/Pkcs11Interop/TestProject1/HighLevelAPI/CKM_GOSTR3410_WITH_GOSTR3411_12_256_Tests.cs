using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Tests;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Net.Pkcs11Interop.Common;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class CKM_GOSTR3410_WITH_GOSTR3411_12_256_Tests
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

                    // Generate key pair
                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
                    Helpers.GenerateKeyPair512(session, out publicKey, out privateKey);

                    Mechanism mechanism = new Mechanism(CKM.CKM_GOSTR3411_12_256);

                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");

                    byte[] data = session.Digest(mechanism, sourceData);

                    // Specify signing mechanism
                    mechanism = new Mechanism(CKM.CKM_GOSTR3410_WITH_GOSTR3411_12_256);

                    // Sign data
                    byte[] signature = session.Sign(mechanism, privateKey, data);

                    // Do something interesting with signature

                    // Verify function is not avilale in CKM_GOSTR3410_WITH_GOSTR3411 mechanism
                    // Verify signature
                    //bool isValid = false;

                    //session.Verify(mechanism, publicKey, sourceData, signature, out isValid);

                    // Do something interesting with verification result
                    //Assert.IsTrue(isValid);

                    session.DestroyObject(privateKey);
                    session.DestroyObject(publicKey);
                    session.Logout();
                }
            }
        }
    }
}
