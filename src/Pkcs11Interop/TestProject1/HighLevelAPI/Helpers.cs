/*
 *  Copyright 2012-2016 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;

namespace Net.Pkcs11Interop.Tests.HighLevelAPI
{
    /// <summary>
    /// Helper methods for HighLevelAPI tests.
    /// </summary>
    public static class Helpers
    {
        /// <summary>
        /// Finds slot containing the token that matches criteria specified in Settings class
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <returns>Slot containing the token that matches criteria</returns>
        public static Slot GetUsableSlot(Pkcs11 pkcs11)
        {
            // Get list of available slots with token present
            List<Slot> slots = pkcs11.GetSlotList(true);

            Assert.IsNotNull(slots);
            Assert.IsTrue(slots.Count > 0);

            // First slot with token present is OK...
            Slot matchingSlot = slots[0];

            // ...unless there are matching criteria specified in Settings class
            if (Settings.TokenSerial != null || Settings.TokenLabel != null)
            {
                matchingSlot = null;

                foreach (Slot slot in slots)
                {
                    TokenInfo tokenInfo = null;

                    try
                    {
                        tokenInfo = slot.GetTokenInfo();
                    }
                    catch (Pkcs11Exception ex)
                    {
                        if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                            throw;
                    }

                    if (tokenInfo == null)
                        continue;

                    if (!string.IsNullOrEmpty(Settings.TokenSerial))
                        if (0 != string.Compare(Settings.TokenSerial, tokenInfo.SerialNumber, StringComparison.Ordinal))
                            continue;

                    if (!string.IsNullOrEmpty(Settings.TokenLabel))
                        if (0 != string.Compare(Settings.TokenLabel, tokenInfo.Label, StringComparison.Ordinal))
                            continue;

                    matchingSlot = slot;
                    break;
                }
            }

            Assert.IsTrue(matchingSlot != null, "Token matching criteria specified in Settings class is not present");
            return matchingSlot;
        }

        /// <summary>
        /// Finds slot containing the token that matches criteria specified in Settings class
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <returns>Slot containing the token that matches criteria</returns>
        public static Slot GetUsableSlot11(Pkcs11 pkcs11)
        {
            // Get list of available slots with token present
            List<Slot> slots = pkcs11.GetSlotList(true);

            Assert.IsNotNull(slots);
            Assert.IsTrue(slots.Count > 0);

            // First slot with token present is OK...
            Slot matchingSlot = slots[0];

            // ...unless there are matching criteria specified in Settings class
            if (Settings.TokenSerial != null || Settings.TokenLabel != null)
            {
                matchingSlot = null;

                foreach (Slot slot in slots)
                {
                    TokenInfo tokenInfo = null;


                    try
                    {
                        tokenInfo = slot.GetTokenInfo();

                    }
                    catch (Pkcs11Exception ex)
                    {
                        if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                            throw;
                    }

                    if (tokenInfo == null)
                        continue;

                    if (!string.IsNullOrEmpty(Settings.TokenSerial))
                        if (0 != string.Compare(Settings.TokenSerial, tokenInfo.SerialNumber, StringComparison.Ordinal))
                            continue;

                    if (!string.IsNullOrEmpty(Settings.TokenLabel))
                        if (0 != string.Compare(Settings.TokenLabel, tokenInfo.Label, StringComparison.Ordinal))
                            continue;

                    matchingSlot = slot;
                    break;
                }
            }

            Assert.IsTrue(matchingSlot != null, "Token matching criteria specified in Settings class is not present");
            return matchingSlot;
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
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_DATA));
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
            byte[] ckaId = session.GenerateRandom(20);

            byte[] value = session.GenerateRandom(20);

            byte[] GOST28147_params_oid = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };                    // Prepare attribute template of new key
            List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
            //objectAttributes.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
            objectAttributes.Add(new ObjectAttribute(CKA.CKA_GOST28147PARAMS, GOST28147_params_oid));

            // Specify key generation mechanism
            Mechanism mechanism = new Mechanism(CKM.CKM_GOST28147_KEY_GEN);

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
            byte[] ckaId = session.GenerateRandom(20);
            byte[] GOST3410_params_oid = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };
            byte[] GOST3411_params_oid = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 };
            byte[] GOST28147_params_oid = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };
            byte[] subject = { 0x06, 0x07, 0x2a };

                    // Prepare attribute template of new public key
            List<ObjectAttribute> publicKeyAttributes = new List<ObjectAttribute>();
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOSTR3410));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
                    //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
                    //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY, true));
            publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_GOSTR3410PARAMS, GOST3410_params_oid));
                    //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_GOSTR3411PARAMS, GOST3411_params_oid));
                    //publicKeyAttributes.Add(new ObjectAttribute(CKA.CKA_GOST28147PARAMS, GOST28147_params_oid));

                    // Prepare attribute template of new private key
            List<ObjectAttribute> privateKeyAttributes = new List<ObjectAttribute>();
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, Settings.ApplicationName));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_ID, ckaId));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOSTR3410));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_DERIVE, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, subject));
                    //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));
                    //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, true));
                    //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
                    //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
                    //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN, true));
                    //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_GOSTR3410PARAMS, GOST3410_params_oid));
            privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_GOSTR3411PARAMS, GOST3411_params_oid));
                    //privateKeyAttributes.Add(new ObjectAttribute(CKA.CKA_GOST28147PARAMS, GOST28147_params_oid));

                    // Specify key generation mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

                    // Generate key pair
                    session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

                
            
        }


        /// <summary>
        /// Generates asymetric key pair 512.
        /// </summary>
        /// <param name='session'>Read-write session with user logged in</param>
        /// <param name='publicKeyHandle'>Output parameter for public key object handle</param>
        /// <param name='privateKeyHandle'>Output parameter for private key object handle</param>
        public static void GenerateKeyPair512(Session session, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle)
        {
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
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);



        }
    }
}

/*
 *  Copyright 2012-2016 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */
 