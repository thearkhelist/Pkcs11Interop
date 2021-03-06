/*
 *  Pkcs11Interop - Open-source .NET wrapper for unmanaged PKCS#11 libraries
 *  Copyright (C) 2012 Jaroslav Imrich <jimrich(at)jimrich(dot)sk>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  If this license does not suit your needs you can purchase a commercial
 *  license from Pkcs11Interop author.
 */

using NUnit.Framework;
using System;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Common;
using System.Text;
using System.IO;

namespace Net.Pkcs11Interop.Tests.HighLevelAPI
{
    /// <summary>
    /// Digesting tests.
    /// </summary>
    [TestFixture()]
    public class DigestTest
    {
        /// <summary>
        /// Single-part digesting test.
        /// </summary>
        [Test()]
        public void DigestSinglePartTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);
                
                // Open RO session
                using (Session session = slot.OpenSession(true))
                {
                    // Specify digesting mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_SHA_1);
                    
                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");
                    
                    // Digest data
                    byte[] digest = session.Digest(mechanism, sourceData);
                    
                    // Do something interesting with digest value
                    Assert.IsTrue(Convert.ToBase64String(digest) == "e1AsOh9IyGCa4hLN+2Od7jlnP14=");
                }
            }
        }

        /// <summary>
        /// Multi-part digesting test.
        /// </summary>
        [Test()]
        public void DigestMultiPartTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);
                
                // Open RO session
                using (Session session = slot.OpenSession(true))
                {
                    // Specify digesting mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_SHA_1);
                    
                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");
                    byte[] digest = null;
                    
                    // Multipart digesting can be used i.e. for digesting of streamed data
                    using (MemoryStream inputStream = new MemoryStream(sourceData))
                    {
                        // Digest data
                        digest = session.Digest(mechanism, inputStream);
                    }

                    // Do something interesting with digest value
                    Assert.IsTrue(Convert.ToBase64String(digest) == "e1AsOh9IyGCa4hLN+2Od7jlnP14=");
                }
            }
        }
        
        /// <summary>
        /// DigestKey test.
        /// </summary>
        [Test()]
        public void DigestKeyTest() // TODO - Test on device that supports this method
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, false))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);
                
                // Open RW session
                using (Session session = slot.OpenSession(false))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);
                    
                    // Generate symetric key
                    ObjectHandle generatedKey = Helpers.GenerateKey(session);

                    // Specify digesting mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_SHA_1);
                    
                    // Digest key
                    byte[] digest = session.DigestKey(mechanism, generatedKey);
                    
                    // Do something interesting with digest value
                    Assert.IsNotNull(digest);

                    session.DestroyObject(generatedKey);
                    session.Logout();
                }
            }
        }
    }
}

