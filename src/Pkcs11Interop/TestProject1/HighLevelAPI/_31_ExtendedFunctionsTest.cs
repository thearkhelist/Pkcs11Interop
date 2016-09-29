using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Tests;
using Net.Pkcs11Interop.Tests.HighLevelAPI;
using Net.Pkcs11Interop.Common;

namespace TestProject1.HighLevelAPI
{
    [TestClass]
    public class _31_ExtendedFunctionsTest
    {
        // <summary>
        /// Basic TokenExtendedInfoTest test.
        /// </summary>
        [TestMethod]
        public void _01_TokenExtendedInfoTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Get token info
                TokenInfo info = slot.GetTokenInfo();
                TokenInfoExtended tokenInfo = slot.GetTokenInfoExtended();

                Assert.IsTrue(tokenInfo.TokenClass == TOKEN_CLASS.TOKEN_CLASS_ECP);
                          
                // Do something interesting with token info
                Assert.IsFalse(String.IsNullOrEmpty(tokenInfo.SerialNumber));

            }
        }

        [TestMethod]
        public void _02_ExtendedInitTokenTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);
                TokenInfo info = slot.GetTokenInfo();
                TokenInfoExtended tokenInfo = slot.GetTokenInfoExtended();
                slot.InitTokenExtended(Settings.SecurityOfficerPin, Settings.NormalUserPin, Settings.ApplicationName);

            }
        }


        /// <summary>
        /// UnlockPinTest test.
        /// </summary>
        [TestMethod]
        public void _03_UnlockPinTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                TokenInfoExtended tokenInfo = slot.GetTokenInfoExtended();

                // Open RO session
                using (Session session = slot.OpenSession(false))
                { 
                    for (int i = 0; i < tokenInfo.MaxUserRetryCount; i++)
                    {
                        try
                        {
                            // Login as User with wrong password to block pin
                            session.Login(CKU.CKU_USER, Settings.WrongUserPin);
                        }
                        catch
                        {
                        }
                    }
                    //Login as SO to unlock user pin
                    session.Login(CKU.CKU_SO, Settings.SecurityOfficerPin);
                    session.UnlockUserPin();
                    session.Logout();
                    // Login as User to check
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);
                    session.Logout();                    
                }
            }
        }

        [TestMethod]
        public void _04_SetAndGetTokenNameTest()
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
                    session.SetTokenName(Settings.LongApplicationName);
                    TokenInfo info = slot.GetTokenInfo();
                    string tmp = ConvertUtils.BytesToUtf8String(ConvertUtils.Utf8StringToBytes(Settings.LongApplicationName, 32, 0x20));
                    Assert.IsTrue(tmp.Equals(info.Label));
                    string newTokenName = session.GetTokenName();
                    Assert.IsTrue(Settings.LongApplicationName == newTokenName);
                    session.Logout();
                }

            }
        }

        [TestMethod]
        public void _05_SetLocalPinTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present

                Slot slot = Helpers.GetUsableSlot(pkcs11);
                using (Session session = slot.OpenSession(false))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_SO, Settings.SecurityOfficerPin);
                    session.InitPin(Settings.NormalUserPin);
                    session.Logout();
                }
                slot.SetLocalPIN(Settings.NormalUserPin, Settings.LocalUserPin);
                slot.SetLocalPIN(Settings.LocalUserPin, Settings.NormalUserPin);
                slot.CloseAllSessions();

            }
        }

        [TestMethod]
        public void _06_SetAndGetLicenseTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RW session
                using (Session session = slot.OpenSession(false))
                {
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);
                    TokenInfo info = slot.GetTokenInfo();
                    byte[] license = session.GenerateRandom(72);
                    session.SetLicense(license);
                    byte[] getLicense = new byte[72];
                    session.GetLicense(getLicense);
                    session.Logout();
                }

            }
        }

    }
}
