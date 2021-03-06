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
using Net.Pkcs11Interop.Common;

namespace Net.Pkcs11Interop.HighLevelAPI.MechanismParams
{
    /// <summary>
    /// Parameters for the CKM_SSL3_PRE_MASTER_KEY_GEN mechanism
    /// </summary>
    public class CkVersion : IMechanismParams
    {
        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private LowLevelAPI.CK_VERSION _lowLevelStruct = new LowLevelAPI.CK_VERSION();

        /// <summary>
        /// Major version number (the integer portion of the version)
        /// </summary>
        public byte Major
        {
            get
            {
                return _lowLevelStruct.Major[0];
            }
        }

        /// <summary>
        /// Minor version number (the hundredths portion of the version)
        /// </summary>
        public byte Minor
        {
            get
            {
                return _lowLevelStruct.Minor[0];
            }
        }

        /// <summary>
        /// Initializes a new instance of the CkVersion class.
        /// </summary>
        /// <param name='major'>Major version number (the integer portion of the version)</param>
        /// <param name='minor'>Minor version number (the hundredths portion of the version)</param>
        public CkVersion(byte major, byte minor)
        {
            _lowLevelStruct.Major = new byte[] { major };
            _lowLevelStruct.Minor = new byte[] { minor };
        }
        
        #region IMechanismParams
        
        /// <summary>
        /// Converts object to low level mechanism parameters
        /// </summary>
        /// <returns>Low level mechanism parameters</returns>
        public object ToLowLevelParams()
        {
            return _lowLevelStruct;
        }
        
        #endregion

        /// <summary>
        /// Returns a string that represents the current CkVersion object.
        /// </summary>
        /// <returns>String that represents the current CkVersion object.</returns>
        public override string ToString()
        {
            return ConvertUtils.CkVersionToString(_lowLevelStruct);
        }
    }
}
