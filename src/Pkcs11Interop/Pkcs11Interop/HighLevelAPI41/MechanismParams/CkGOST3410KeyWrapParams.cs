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
using Net.Pkcs11Interop.LowLevelAPI41.MechanismParams;

namespace Net.Pkcs11Interop.HighLevelAPI41.MechanismParams
{
    /// <summary>
    /// Parameters for the CKM_CMS_SIG mechanism
    /// </summary>
    public class CkGOST3410KeyWrapParams : IMechanismParams, IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;
        
        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private CK_GOST3410_KEY_WRAP_PARAMS _lowLevelStruct = new CK_GOST3410_KEY_WRAP_PARAMS();

        /// <summary>
        /// Initializes a new instance of the CkCmsSigParams class.
        /// </summary>
        /// <param name='hKey'>key handle. Key handle of a sender\receiver for C_WrapKey\C_UnwrapKey operation. When key handle takes CK_INVALID_HANDLE value then an ephemeral (one time) key pair of a sender will be used</param>
        /// <param name='pWrapOID'>length of data with DER-encoding of the object identifier indicating the data object type of GOST 28147-89</param>
        /// <param name='pUKM'>pointer to a data with UKM. If pointer takes NULL_PTR value in C_WrapKey operation then random value of UKM will be used.If pointer takes non-NULL_PTR value in C_UnwrapKey operation then the pointer value will be compared with UKM value of wrapped key.If these two values do not match the wrapped key will be rejected</param>
        public CkGOST3410KeyWrapParams(ObjectHandle hKey, byte[] pWrapOID, byte[] pUKM)
        {
            _lowLevelStruct.hKey = CK.CK_INVALID_HANDLE;
            _lowLevelStruct.pWrapOID = IntPtr.Zero;
            _lowLevelStruct.ulWrapOIDLen = 0;
            _lowLevelStruct.pUKM = IntPtr.Zero;
            _lowLevelStruct.ulUKMLen = 0;

            if (hKey == null)
                throw new ArgumentNullException("keyHandle");
            _lowLevelStruct.hKey = hKey.ObjectId;

            if (pWrapOID != null)
            {
                byte[] bytes = pWrapOID;
                _lowLevelStruct.pWrapOID = UnmanagedMemory.Allocate(bytes.Length);
                UnmanagedMemory.Write(_lowLevelStruct.pWrapOID, bytes);
                _lowLevelStruct.ulWrapOIDLen = Convert.ToUInt64((pWrapOID.ToString()).Length);
            }
            if (pUKM != null)
            {
                byte[] bytes = pUKM;
                _lowLevelStruct.pUKM = UnmanagedMemory.Allocate(bytes.Length);
                UnmanagedMemory.Write(_lowLevelStruct.pUKM, bytes);
                _lowLevelStruct.ulUKMLen = Convert.ToUInt64((pUKM.ToString()).Length);
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
                UnmanagedMemory.Free(ref _lowLevelStruct.pWrapOID);
                UnmanagedMemory.Free(ref _lowLevelStruct.pUKM);
                _lowLevelStruct.hKey = 0;
                _lowLevelStruct.ulWrapOIDLen = 0;
                _lowLevelStruct.ulUKMLen = 0;

                _disposed = true;
            }
        }
        
        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~CkGOST3410KeyWrapParams()
        {
            Dispose(false);
        }
        
        #endregion
    }
}
