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
using System.Runtime.InteropServices;

namespace Net.Pkcs11Interop.LowLevelAPI.MechanismParams
{
    /// <summary>
    /// Structure that provides the parameters to the CKM_SKIPJACK_PRIVATE_WRAP mechanism
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS
    {
        /// <summary>
        /// Length of the password
        /// </summary>
        public uint PasswordLen;
        
        /// <summary>
        /// Pointer to the buffer which contains the user-supplied password
        /// </summary>
        public IntPtr Password;

        /// <summary>
        /// Other party's key exchange public key size
        /// </summary>
        public uint PublicDataLen;

        /// <summary>
        /// Pointer to other party's key exchange public key value
        /// </summary>
        public IntPtr PublicData;
        
        /// <summary>
        /// Length of prime and base values
        /// </summary>
        public uint PAndGLen;

        /// <summary>
        /// Length of subprime value
        /// </summary>
        public uint QLen;

        /// <summary>
        /// Size of random Ra, in bytes
        /// </summary>
        public uint RandomLen;

        /// <summary>
        /// Pointer to Ra data
        /// </summary>
        public IntPtr RandomA;

        /// <summary>
        /// Pointer to Prime, p, value
        /// </summary>
        public IntPtr PrimeP;

        /// <summary>
        /// Pointer to Base, g, value
        /// </summary>
        public IntPtr BaseG;

        /// <summary>
        /// Pointer to Subprime, q, value
        /// </summary>
        public IntPtr SubprimeQ;
    }
}
