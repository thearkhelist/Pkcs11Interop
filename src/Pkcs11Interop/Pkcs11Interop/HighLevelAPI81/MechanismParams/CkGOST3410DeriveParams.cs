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
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81.MechanismParams;

namespace Net.Pkcs11Interop.HighLevelAPI81.MechanismParams
{
    /// <summary>
    /// Parameters for the CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE key derivation mechanisms
    /// </summary>
    public class CkGOST3410DeriveParams : IMechanismParams, IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;
        
        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private CK_GOST3410_DERIVE_PARAMS _lowLevelStruct = new CK_GOST3410_DERIVE_PARAMS();

        /// <summary>
        /// Initializes a new instance of the CkGOST3410DeriveParams class.
        /// </summary>
        /// <param name='kdf'>Key derivation function used on the shared secret value (CKD)</param>
        /// <param name='UKM'>Some data shared between the two parties</param>
        /// <param name='publicData'>Other party's EC public key value</param>
        public CkGOST3410DeriveParams(ulong kdf, byte[] UKM, byte[] publicData)
        {
            _lowLevelStruct.kdf = 0;
            _lowLevelStruct.pPublicData = IntPtr.Zero;
            _lowLevelStruct.ulPublicDataLen = 0;
            _lowLevelStruct.pUKM = IntPtr.Zero;
            _lowLevelStruct.ulUkmLen = 0;

            _lowLevelStruct.kdf = kdf;

            if (publicData != null)
            {
                _lowLevelStruct.pPublicData = UnmanagedMemory.Allocate(publicData.Length);
                UnmanagedMemory.Write(_lowLevelStruct.pPublicData, publicData);
                _lowLevelStruct.ulPublicDataLen = Convert.ToUInt64(publicData.Length);
            }

            if (UKM != null)
            {
                _lowLevelStruct.pUKM = UnmanagedMemory.Allocate(UKM.Length);
                UnmanagedMemory.Write(_lowLevelStruct.pUKM, UKM);
                _lowLevelStruct.ulUkmLen = Convert.ToUInt64(UKM.Length);
            }

        }
        
        #region IMechanismParams
        
        /// <summary>
        /// Returns managed object that can be marshaled to an unmanaged block of memory
        /// </summary>
        /// <returns>A managed object holding the data to be marshaled. This object must be an instance of a formatted class.</returns>
        public object ToMarshalableStructure()
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
                UnmanagedMemory.Free(ref _lowLevelStruct.pUKM);
                _lowLevelStruct.ulUkmLen = 0;
                UnmanagedMemory.Free(ref _lowLevelStruct.pPublicData);
                _lowLevelStruct.ulPublicDataLen = 0;

                _disposed = true;
            }
        }
        
        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~CkGOST3410DeriveParams()
        {
            Dispose(false);
        }
        
        #endregion
    }
}
