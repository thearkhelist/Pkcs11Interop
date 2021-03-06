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
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI;
using System.Text;

namespace Net.Pkcs11Interop.Tests.LowLevelAPI
{
    /// <summary>
    /// C_GetSlotList, C_GetSlotInfo and C_WaitForSlotEvent tests.
    /// </summary>
    [TestFixture()]
    public class SlotListInfoAndEventTest
    {
        /// <summary>
        /// C_GetSlotList test.
        /// </summary>
        [Test()]
        public void SlotListTest()
        {
            CKR rv = CKR.CKR_OK;
            
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(null);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());
                
                // Get number of slots in first call
                uint slotCount = 0;
                rv = pkcs11.C_GetSlotList(true, null, ref slotCount);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                Assert.IsTrue(slotCount > 0);
                
                // Allocate array for slot IDs
                uint[] slotList = new uint[slotCount];
                
                // Get slot IDs in second call
                rv = pkcs11.C_GetSlotList(true, slotList, ref slotCount);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Do something interesting with slots

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// C_GetSlotInfo test.
        /// </summary>
        [Test()]
        public void BasicSlotListAndInfoTest()
        {
            CKR rv = CKR.CKR_OK;
            
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(null);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());
                
                // Get number of slots in first call
                uint slotCount = 0;
                rv = pkcs11.C_GetSlotList(true, null, ref slotCount);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                Assert.IsTrue(slotCount > 0);
                
                // Allocate array for slot IDs
                uint[] slotList = new uint[slotCount];
                
                // Get slot IDs in second call
                rv = pkcs11.C_GetSlotList(true, slotList, ref slotCount);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Analyze first slot
                CK_SLOT_INFO slotInfo = new CK_SLOT_INFO();
                rv = pkcs11.C_GetSlotInfo(slotList[0], ref slotInfo);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                
                // Do something interesting with slot info
                Assert.IsFalse(String.IsNullOrEmpty(ConvertUtils.BytesToUtf8String(slotInfo.ManufacturerId)));
                
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// C_WaitForSlotEvent test.
        /// </summary>
        [Test()]
        public void WaitForSlotEventTest()
        {
            CKR rv = CKR.CKR_OK;
            
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(null);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Wait for a slot event
                uint slot = 0;
                rv = pkcs11.C_WaitForSlotEvent(CKF.CKF_DONT_BLOCK, ref slot, IntPtr.Zero);
                if (rv != CKR.CKR_NO_EVENT)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
    }
}

