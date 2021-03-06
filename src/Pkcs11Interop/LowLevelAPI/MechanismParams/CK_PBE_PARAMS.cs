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
    /// Structure which provides all of the necessary information required by the CKM_PBE mechanisms and the CKM_PBA_SHA1_WITH_SHA1_HMAC mechanism
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_PBE_PARAMS
    {
        /// <summary>
        /// Pointer to the location that receives the 8-byte initialization vector (IV), if an IV is required
        /// </summary>
        public IntPtr InitVector;

        /// <summary>
        /// Points to the password to be used in the PBE key generation
        /// </summary>
        public IntPtr Password;

        /// <summary>
        /// Length in bytes of the password information
        /// </summary>
        public uint PasswordLen;

        /// <summary>
        /// Points to the salt to be used in the PBE key generation
        /// </summary>
        public IntPtr Salt;

        /// <summary>
        /// Length in bytes of the salt information
        /// </summary>
        public uint SaltLen;

        /// <summary>
        /// Number of iterations required for the generation
        /// </summary>
        public uint Iteration;
    }
}
