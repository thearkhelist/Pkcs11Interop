﻿/*
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
using System.Collections.Generic;
using System.Text;
using Net.Pkcs11Interop.Common;

namespace Net.Pkcs11Interop.HighLevelAPI
{
    /// <summary>
    /// Logical reader that potentially contains a token
    /// </summary>
    public class Slot
    {
        /// <summary>
        /// Low level PKCS#11 wrapper
        /// </summary>
        private LowLevelAPI.Pkcs11 _p11 = null;

        /// <summary>
        /// PKCS#11 handle of slot
        /// </summary>
        private uint _slotId = CK.CK_INVALID_HANDLE;
        
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
        internal Slot(LowLevelAPI.Pkcs11 pkcs11, uint slotId)
        {
            if (pkcs11 == null)
                throw new ArgumentNullException("pkcs11");
            
            if (slotId == CK.CK_INVALID_HANDLE)
                throw new ArgumentException("Invalid handle specified", "slotId");

            _p11 = pkcs11;
            _slotId = slotId;
        }

        /// <summary>
        /// Obtains information about a particular slot in the system
        /// </summary>
        /// <returns>Slot information</returns>
        public SlotInfo GetSlotInfo()
        {
            LowLevelAPI.CK_SLOT_INFO slotInfo = new LowLevelAPI.CK_SLOT_INFO();
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
            LowLevelAPI.CK_TOKEN_INFO tokenInfo = new LowLevelAPI.CK_TOKEN_INFO();
            CKR rv = _p11.C_GetTokenInfo(_slotId, ref tokenInfo);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetTokenInfo", rv);

            return new TokenInfo(_slotId, tokenInfo);
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
                Array.Resize(ref mechanismList, (int)mechanismCount);

            return new List<CKM>(mechanismList);
        }

        /// <summary>
        /// Obtains information about a particular mechanism possibly supported by a token
        /// </summary>
        /// <param name="mechanism">Mechanism</param>
        /// <returns>Information about mechanism</returns>
        public MechanismInfo GetMechanismInfo(CKM mechanism)
        {
            LowLevelAPI.CK_MECHANISM_INFO mechanismInfo = new LowLevelAPI.CK_MECHANISM_INFO();
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
                soPinValueLen = (uint)soPinValue.Length;
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
                soPinValueLen = (uint)soPin.Length;
            }

            // PKCS #11 v2.20 - page 113
            // pLabel points to the 32-byte label of the token (which must be padded with
            // blank characters, and which must not be null-terminated).
            byte[] tokenLabel = new byte[32];
            for (int i = 0; i < tokenLabel.Length; i++)
                tokenLabel [i] = 0x20;
            
            if (label != null)
            {
                if (label.Length > 32)
                    throw new Pkcs11InteropException("Label too long");
                Array.Copy(label, 0, tokenLabel, 0, label.Length);
            }
            
            CKR rv = _p11.C_InitToken(_slotId, soPinValue, soPinValueLen, tokenLabel);
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
