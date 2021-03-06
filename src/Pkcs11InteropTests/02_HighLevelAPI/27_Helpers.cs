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

using System;
using Net.Pkcs11Interop.HighLevelAPI;
using System.Collections.Generic;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;

namespace Net.Pkcs11Interop.Tests.HighLevelAPI
{
    /// <summary>
    /// Helper methods for HighLevelAPI tests.
    /// </summary>
    public class Helpers
    {
        /// <summary>
        /// Finds first slot with token present
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <returns>First slot with token present</returns>
        public static Slot GetUsableSlot(Pkcs11 pkcs11)
        {
            // Get list of available slots
            List<Slot> slots = pkcs11.GetSlotList(true);

            Assert.IsNotNull(slots);
            Assert.IsTrue(slots.Count > 0);

            // Let's use first slot with token present
            return slots[0];
        }

        /// <summary>
        /// Creates the data object.
        /// </summary>
        /// <param name='session'>Read-write session with user logged in</param>
        /// <returns>Object handle</returns>
        public static ObjectHandle CreateDataObject(Session session)
        {
            // Prepare attribute template of new data object
            List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, (uint)CKO.CKO_DATA));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_APPLICATION, Settings.ApplicationName));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, "Data object content"));
            
            // Create object
            return session.CreateObject(objectAttributes);
        }

        /// <summary>
        /// Generates symetric key.
        /// </summary>
        /// <param name='session'>Read-write session with user logged in</param>
        /// <returns>Object handle</returns>
        public static ObjectHandle GenerateKey(Session session)
        {
            // Prepare attribute template of new key
            List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, (uint)CKO.CKO_SECRET_KEY));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_DERIVE, true));
            
            // Specify key generation mechanism
            Mechanism mechanism = new Mechanism(CKM.CKM_DES3_KEY_GEN);
            
            // Generate key
            return session.GenerateKey(mechanism, objectAttributes);
        }

        /// <summary>
        /// Generates asymetric key pair.
        /// </summary>
        /// <param name='session'>Read-write session with user logged in</param>
        /// <param name='publicKeyHandle'>Output parameter for public key object handle</param>
        /// <param name='privateKeyHandle'>Output parameter for private key object handle</param>
        public static void GenerateKeyPair(Session session, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle)
        {
            // The CKA_ID attribute is intended as a means of distinguishing multiple key pairs held by the same subject
            byte[] ckaId = session.GenerateRandom(20);
            
            // Prepare attribute template of new public key
            List<ObjectAttribute> publicKeyAttributes = new List<ObjectAttribute>();
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY, true));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY_RECOVER, true));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS_BITS, 1024));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, new byte[] { 0x01, 0x00, 0x01 }));
            
            // Prepare attribute template of new private key
            List<ObjectAttribute> privateKeyAttributes = new List<ObjectAttribute>();
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN_RECOVER, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));
            
            // Specify key generation mechanism
            Mechanism mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
            
            // Generate key pair
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
        }
    }
}
