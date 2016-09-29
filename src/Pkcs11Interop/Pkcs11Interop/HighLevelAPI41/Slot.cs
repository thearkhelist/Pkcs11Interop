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

using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;

namespace Net.Pkcs11Interop.HighLevelAPI41
{
    /// <summary>
    /// Logical reader that potentially contains a token
    /// </summary>
    public class Slot
    {
        /// <summary>
        /// Low level PKCS#11 wrapper
        /// </summary>
        private LowLevelAPI41.Pkcs11 _p11 = null;

        /// <summary>
        /// Low level PKCS#11 wrapper. Use with caution!
        /// </summary>
        public LowLevelAPI41.Pkcs11 LowLevelPkcs11
        {
            get
            {
                return _p11;
            }
        }

        /// <summary>
        /// PKCS#11 handle of slot
        /// </summary>
        private uint _slotId = 0;
        
        /// <summary>
        /// PKCS#11 handle of slot
        /// </summary>
        public uint SlotId
        {
            get
            {
                return _slotId;
            }
        }

        /// <summary>
        /// Initializes new instance of Slot class
        /// </summary>
        /// <param name="pkcs11">Low level PKCS#11 wrapper</param>
        /// <param name="slotId">PKCS#11 handle of slot</param>
        internal Slot(LowLevelAPI41.Pkcs11 pkcs11, uint slotId)
        {
            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");

            _p11 = pkcs11;
            _slotId = slotId;
        }

        /// <summary>
        /// Obtains information about a particular slot in the system
        /// </summary>
        /// <returns>Slot information</returns>
        public SlotInfo GetSlotInfo()
        {
            CK_SLOT_INFO slotInfo = new CK_SLOT_INFO();
            CKR rv = _p11.C_GetSlotInfo(_slotId, ref slotInfo);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetSlotInfo", rv);

            return new SlotInfo(_slotId, slotInfo);
        }

        /// <summary>
        /// Obtains information about a particular token in the system.
        /// </summary>
        /// <returns>Token information</returns>
        public TokenInfo GetTokenInfo()
        {
            CK_TOKEN_INFO tokenInfo = new CK_TOKEN_INFO();
            uint size =  Convert.ToUInt32(Common.UnmanagedMemory.SizeOf(typeof(CK_TOKEN_INFO)));
            CKR rv = _p11.C_GetTokenInfo(_slotId, ref tokenInfo);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetTokenInfo", rv);

            return new TokenInfo(_slotId, tokenInfo);
        }

        /// <summary>
        /// Obtains extended information about a particular token in the system.
        /// </summary>
        /// <returns>Token information</returns>
        public TokenInfoExtended GetTokenInfoExtended()
        {
            CK_TOKEN_INFO_EXTENDED tokenInfo = new CK_TOKEN_INFO_EXTENDED();
            tokenInfo.ulSizeofThisStructure = Convert.ToUInt32(Common.UnmanagedMemory.SizeOf(typeof(CK_TOKEN_INFO_EXTENDED)));
            CKR rv = _p11.C_EX_GetTokenInfoExtended(_slotId, ref tokenInfo);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetTokenInfoExtended", rv);

            return new TokenInfoExtended(_slotId, tokenInfo);
        }

        /// <summary>
        /// Modifies the PIN of the user that is currently logged in, or the CKU_USER PIN if the session is not logged in.
        /// </summary>
        /// <param name="oldPin">Old PIN value</param>
        /// <param name="newPin">New PIN value</param>
        public void SetLocalPIN(string oldPin, string newPin)
        {
            byte[] userPinValue = null;
            uint userPinValueLen = 0;
            if (oldPin != null)
            {
                userPinValue = ConvertUtils.Utf8StringToBytes(oldPin);
                userPinValueLen = Convert.ToUInt32(userPinValue.Length);
            }

            byte[] newPinValue = null;
            uint newPinValueLen = 0;
            if (newPin != null)
            {
                newPinValue = ConvertUtils.Utf8StringToBytes(newPin);
                newPinValueLen = Convert.ToUInt32(newPinValue.Length);
            }

            CKR rv = _p11.C_EX_SetLocalPIN(_slotId, userPinValue, userPinValueLen, newPinValue, newPinValueLen, 0x1F);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_SetLocalPIN", rv);
        }





        /// <summary>
        /// Obtains a list of mechanism types supported by a token
        /// </summary>
        /// <returns>List of mechanism types supported by a token</returns>
        public List<CKM> GetMechanismList()
        {
            uint mechanismCount = 0;
            CKR rv = _p11.C_GetMechanismList(_slotId, null, ref mechanismCount);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetMechanismList", rv);

            if (mechanismCount < 1)
                return new List<CKM>();

            CKM[] mechanismList = new CKM[mechanismCount];
            rv = _p11.C_GetMechanismList(_slotId, mechanismList, ref mechanismCount);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetMechanismList", rv);

            if (mechanismList.Length != mechanismCount)
                Array.Resize(ref mechanismList, Convert.ToInt32(mechanismCount));

            return new List<CKM>(mechanismList);
        }

        /// <summary>
        /// Obtains information about a particular mechanism possibly supported by a token
        /// </summary>
        /// <param name="mechanism">Mechanism</param>
        /// <returns>Information about mechanism</returns>
        public MechanismInfo GetMechanismInfo(CKM mechanism)
        {
            CK_MECHANISM_INFO mechanismInfo = new CK_MECHANISM_INFO();
            CKR rv = _p11.C_GetMechanismInfo(_slotId, mechanism, ref mechanismInfo);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetMechanismInfo", rv);
            
            return new MechanismInfo(mechanism, mechanismInfo);
        }

        /// <summary>
        /// Initializes a token
        /// </summary>
        /// <param name="soPin">SO's initial PIN</param>
        /// <param name="label">Label of the token</param>
        public void InitToken(string soPin, string label)
        {
            byte[] soPinValue = null;
            uint soPinValueLen = 0;
            if (soPin != null)
            {
                soPinValue = ConvertUtils.Utf8StringToBytes(soPin);
                soPinValueLen = Convert.ToUInt32(soPinValue.Length);
            }

            byte[] tokenLabel = ConvertUtils.Utf8StringToBytes(label, 32, 0x20);

            CKR rv = _p11.C_InitToken(_slotId, soPinValue, soPinValueLen, tokenLabel);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_InitToken", rv);
        }

        /// <summary>
        /// Initializes a token
        /// </summary>
        /// <param name="soPin">SO's initial PIN</param>
        /// <param name="label">Label of the token</param>
        public void InitToken(byte[] soPin, byte[] label)
        {
            byte[] soPinValue = null;
            uint soPinValueLen = 0;
            if (soPin != null)
            {
                soPinValue = soPin;
                soPinValueLen = Convert.ToUInt32(soPin.Length);
            }

            // PKCS#11 v2.20 page 113:
            // pLabel points to the 32-byte label of the token (which must be padded with
            // blank characters, and which must not be null-terminated).
            byte[] tokenLabel = new byte[32];
            for (int i = 0; i < tokenLabel.Length; i++)
                tokenLabel[i] = 0x20;

            if (label != null)
            {
                if (label.Length > 32)
                    throw new Exception("Label too long");
                Array.Copy(label, 0, tokenLabel, 0, label.Length);
            }

            CKR rv = _p11.C_InitToken(_slotId, soPinValue, soPinValueLen, tokenLabel);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_InitToken", rv);
        }


        /// <summary>
        /// Initializes a token
        /// </summary>
        /// <param name="soPin">SO's initial PIN</param>
        /// <param name="newUserPIN">SO's initial PIN</param>
        /// <param name="label">Label of the token</param>
        public void InitTokenExtended(string soPin, string newUserPIN, string label)
        {

            byte[] SO_PIN = ConvertUtils.Utf8StringToBytes(soPin);
            uint SO_PIN_Len = Convert.ToUInt32(SO_PIN.Length);
            byte[] NEW_USER_PIN = ConvertUtils.Utf8StringToBytes(newUserPIN);

            CK_RUTOKEN_INIT_PARAM initInfo_st = new CK_RUTOKEN_INIT_PARAM();
            initInfo_st.ulSizeofThisStructure = Convert.ToUInt32(Common.UnmanagedMemory.SizeOf(typeof(CK_RUTOKEN_INIT_PARAM)));
            initInfo_st.UseRepairMode = 0;
            if (soPin != null)
            {
                initInfo_st.pNewAdminPin = UnmanagedMemory.Allocate(SO_PIN.Length);
                UnmanagedMemory.Write(initInfo_st.pNewAdminPin, SO_PIN);
                initInfo_st.ulNewAdminPinLen = Convert.ToUInt32(SO_PIN.Length);
            }
            if (newUserPIN != null)
            {
                initInfo_st.pNewUserPin = UnmanagedMemory.Allocate(NEW_USER_PIN.Length);
                UnmanagedMemory.Write(initInfo_st.pNewUserPin, NEW_USER_PIN);
                initInfo_st.ulNewUserPinLen = Convert.ToUInt32(NEW_USER_PIN.Length);
            }
            initInfo_st.ulMinAdminPinLen = 6;
            initInfo_st.ulMinUserPinLen =  6;
            initInfo_st.ChangeUserPINPolicy = (TOKEN_FLAGS.TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN | TOKEN_FLAGS.TOKEN_FLAGS_USER_CHANGE_USER_PIN);
            initInfo_st.ulMaxAdminRetryCount = 10;
            initInfo_st.ulMaxUserRetryCount = 10;

            if (label != null)
            {
                byte[] tokenLabel = ConvertUtils.Utf8StringToBytes(label, 0x1b, 0x1b);
                initInfo_st.ulLabelLen = Convert.ToUInt32(tokenLabel.Length);
                initInfo_st.pTokenLabel = UnmanagedMemory.Allocate(tokenLabel.Length);
                UnmanagedMemory.Write(initInfo_st.pTokenLabel, tokenLabel);
            }
            

            CKR rv = _p11.C_EX_InitToken(_slotId, SO_PIN, SO_PIN_Len, ref initInfo_st);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_InitToken", rv);
        }

        /// <summary>
        /// Initializes a token
        /// </summary>
        /// <param name="soPin">SO's initial PIN</param>
        /// <param name="label">Label of the token</param>
        public void InitTokenExtended(byte[] soPin, byte[] label)
        {
            char[] Adpin = { '8', '7', '6', '5', '4', '3', '2', '1' };
            /* Новый DEMO PIN-код Пользователя Рутокен */
            char[] Uspin = { '5', '5', '5', '5', '5', '5', '5', '5' };
            //string labelTSL = "Sample Rutoken label";
            //byte[] TOKEN_STD_LABEL = Convert.(labelTSL);
            byte[] TOKEN_STD_LABEL = { 0x70, 0x71 };
            byte[] SO_PIN = new byte[8];
            byte[] NEW_USER_PIN = new byte[8];
            for (int i = 0; i > 8; i++)
            {
                SO_PIN[i] = Convert.ToByte(Adpin[i]);
                NEW_USER_PIN[i] = Convert.ToByte(Uspin[i]);

            }

            CK_RUTOKEN_INIT_PARAM initInfo_st = new CK_RUTOKEN_INIT_PARAM();
            initInfo_st.ulSizeofThisStructure = Convert.ToUInt32(Common.UnmanagedMemory.SizeOf(typeof(CK_RUTOKEN_INIT_PARAM)));
            initInfo_st.UseRepairMode = 0;
            if (SO_PIN != null)
            {
                initInfo_st.pNewAdminPin = UnmanagedMemory.Allocate(SO_PIN.Length);
                UnmanagedMemory.Write(initInfo_st.pNewAdminPin, SO_PIN);
                initInfo_st.ulNewAdminPinLen = Convert.ToUInt32(SO_PIN.Length);
            }
            if (NEW_USER_PIN != null)
            {
                initInfo_st.pNewUserPin = UnmanagedMemory.Allocate(NEW_USER_PIN.Length);
                UnmanagedMemory.Write(initInfo_st.pNewUserPin, NEW_USER_PIN);
                initInfo_st.ulNewUserPinLen = Convert.ToUInt32(NEW_USER_PIN.Length);
            }
            initInfo_st.ulMinAdminPinLen = 6;
            initInfo_st.ulMinUserPinLen = 6;
            initInfo_st.ChangeUserPINPolicy = (TOKEN_FLAGS.TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN | TOKEN_FLAGS.TOKEN_FLAGS_USER_CHANGE_USER_PIN);
            initInfo_st.ulMaxAdminRetryCount = 10;
            initInfo_st.ulMaxUserRetryCount = 10;
            if (TOKEN_STD_LABEL != null)
            {
                initInfo_st.pTokenLabel = UnmanagedMemory.Allocate(TOKEN_STD_LABEL.Length);
                UnmanagedMemory.Write(initInfo_st.pTokenLabel, TOKEN_STD_LABEL);
                initInfo_st.ulLabelLen = Convert.ToUInt32(TOKEN_STD_LABEL.Length);
            }
            initInfo_st.ulLabelLen = 32;
            byte[] soPinValue = null;
            uint soPinValueLen = 0;
            if (soPin != null)
            {
                soPinValue = soPin;
                soPinValueLen = Convert.ToUInt32(soPinValue.Length);
            }

            byte[] tokenLabel = label;

            CKR rv = _p11.C_EX_InitToken(_slotId, soPinValue, soPinValueLen, ref initInfo_st);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_InitToken", rv);
        }

        /// <summary>
        /// Opens a session between an application and a token in a particular slot
        /// </summary>
        /// <param name="readOnly">Flag indicating whether session should be read only</param>
        /// <returns>Session</returns>
        public Session OpenSession(bool readOnly)
        {


            uint flags = CKF.CKF_SERIAL_SESSION;
            if (!readOnly)
                flags = flags | CKF.CKF_RW_SESSION;

            uint sessionId = CK.CK_INVALID_HANDLE;
            CKR rv = _p11.C_OpenSession(_slotId, flags, IntPtr.Zero, IntPtr.Zero, ref sessionId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_OpenSession", rv);

            return new Session(_p11, sessionId);
        }

        /// <summary>
        /// Closes a session between an application and a token
        /// </summary>
        /// <param name="session">Session</param>
        public void CloseSession(Session session)
        {
            if (session == null)
                throw new ArgumentNullException("session");

            session.CloseSession();
        }

        /// <summary>
        /// Closes all sessions an application has with a token
        /// </summary>
        public void CloseAllSessions()
        {
            CKR rv = _p11.C_CloseAllSessions(_slotId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_CloseAllSessions", rv);
        }
    }
}
