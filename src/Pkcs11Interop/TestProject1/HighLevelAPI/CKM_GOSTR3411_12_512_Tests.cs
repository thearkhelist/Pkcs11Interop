using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Tests;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Net.Pkcs11Interop.Common;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class CKM_GOSTR3411_12_512_Tests
    {
        [TestMethod]
        public void _01_DigestSinglePartTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(true))
                {
                    // Specify digesting mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOSTR3411_12_512);

                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world, how do you do?");

                    // Digest data
                    byte[] digest = session.Digest(mechanism, sourceData);

                    // Do something interesting with digest value
                    //Assert.IsTrue(Convert.ToBase64String(digest) == "e1AsOh9IyGCa4hLN+2Od7jlnP14=");
                }
            }
        }
    }
}
