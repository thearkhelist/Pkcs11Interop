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
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.LowLevelAPI;
using Net.Pkcs11Interop.LowLevelAPI.MechanismParams;

namespace Net.Pkcs11Interop.HighLevelAPI.MechanismParams
{
    /// <summary>
    /// Parameters for the CKM_SSL3_KEY_AND_MAC_DERIVE mechanism
    /// </summary>
    public class CkSsl3KeyMatParams : IMechanismParams, IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;
        
        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private LowLevelAPI.MechanismParams.CK_SSL3_KEY_MAT_PARAMS _lowLevelStruct = new LowLevelAPI.MechanismParams.CK_SSL3_KEY_MAT_PARAMS();

        /// <summary>
        /// Resulting key handles and initialization vectors after performing a DeriveKey method
        /// </summary>
        public CkSsl3KeyMatOut ReturnedKeyMaterial
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                // Abrakadabra :)
                UnmanagedMemory.Read(_lowLevelStruct.ReturnedKeyMaterial, _returnedKeyMaterial._lowLevelStruct);
                return _returnedKeyMaterial;
            }
        }

        /// <summary>
        /// Client's and server's random data information
        /// </summary>
        private CkSsl3RandomData _randomInfo = null;

        /// <summary>
        /// Handles for the keys generated and the IVs
        /// </summary>
        private CkSsl3KeyMatOut _returnedKeyMaterial = null;

        /// <summary>
        /// Initializes a new instance of the CkSsl3KeyMatParams class.
        /// </summary>
        /// <param name='macSizeInBits'>The length (in bits) of the MACing keys agreed upon during the protocol handshake phase</param>
        /// <param name='keySizeInBits'>The length (in bits) of the secret keys agreed upon during the protocol handshake phase</param>
        /// <param name='ivSizeInBits'>The length (in bits) of the IV agreed upon during the protocol handshake phase or if no IV is required, the length should be set to 0</param>
        /// <param name='isExport'>Flag indicating whether the keys have to be derived for an export version of the protocol</param>
        /// <param name='randomInfo'>Client's and server's random data information</param>
        public CkSsl3KeyMatParams(uint macSizeInBits, uint keySizeInBits, uint ivSizeInBits, bool isExport, CkSsl3RandomData randomInfo)
        {
            if (randomInfo == null)
                throw new ArgumentNullException("randomInfo");
            
            // Keep reference to randomInfo so GC will not free it while this object exists
            _randomInfo = randomInfo;

            if (ivSizeInBits % 8 != 0)
                throw new ArgumentException("Value has to be a multiple of 8", "ivSizeInBits");

            // GC will not free ReturnedKeyMaterial while this object exists
            _returnedKeyMaterial = new CkSsl3KeyMatOut(ivSizeInBits / 8);

            _lowLevelStruct.MacSizeInBits = macSizeInBits;
            _lowLevelStruct.KeySizeInBits = keySizeInBits;
            _lowLevelStruct.IVSizeInBits = ivSizeInBits;
            _lowLevelStruct.IsExport = isExport;
            _lowLevelStruct.RandomInfo = (CK_SSL3_RANDOM_DATA)_randomInfo.ToLowLevelParams();

            // Abrakadabra :)
            _lowLevelStruct.ReturnedKeyMaterial = UnmanagedMemory.Allocate(UnmanagedMemory.SizeOf(typeof(CK_SSL3_KEY_MAT_OUT)));
            UnmanagedMemory.Write(_lowLevelStruct.ReturnedKeyMaterial, _returnedKeyMaterial._lowLevelStruct);
        }
        
        #region IMechanismParams
        
        /// <summary>
        /// Converts object to low level mechanism parameters
        /// </summary>
        /// <returns>Low level mechanism parameters</returns>
        public object ToLowLevelParams()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            return _lowLevelStruct;
        }
        
        #endregion
        
        #region IDisposable
        
        /// <summary>
        /// Disposes object
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        
        /// <summary>
        /// Disposes object
        /// </summary>
        /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!this._disposed)
            {
                if (disposing)
                {
                    // Dispose managed objects
                }
                
                // Dispose unmanaged objects
                LowLevelAPI.UnmanagedMemory.Free(ref _lowLevelStruct.ReturnedKeyMaterial);
                
                _disposed = true;
            }
        }
        
        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~CkSsl3KeyMatParams()
        {
            Dispose(false);
        }
        
        #endregion
    }
}
