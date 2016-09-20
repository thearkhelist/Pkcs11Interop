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

namespace Net.Pkcs11Interop.HighLevelAPI.MechanismParams
{
    /// <summary>
    /// CkGOST3410KeyWrapParams
    /// </summary>
    public class CkGOST3410KeyWrapParams: IMechanismParams, IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// Platform specific CkCmsSigParams
        /// </summary>
        private HighLevelAPI40.MechanismParams.CkGOST3410KeyWrapParams _params40 = null;

        /// <summary>
        /// Platform specific CkCmsSigParams
        /// </summary>
        private HighLevelAPI41.MechanismParams.CkGOST3410KeyWrapParams _params41 = null;

        /// <summary>
        /// Platform specific CkCmsSigParams
        /// </summary>
        private HighLevelAPI80.MechanismParams.CkGOST3410KeyWrapParams _params80 = null;

        /// <summary>
        /// Platform specific CkCmsSigParams
        /// </summary>
        private HighLevelAPI81.MechanismParams.CkGOST3410KeyWrapParams _params81 = null;

        /// <summary>
        /// Initializes a new instance of the CkCmsSigParams class.
        /// </summary>
        /// <param name='hKey'>key handle. Key handle of a sender\receiver for C_WrapKey\C_UnwrapKey operation. When key handle takes CK_INVALID_HANDLE value then an ephemeral (one time) key pair of a sender will be used</param>
        /// <param name='pWrapOID'>length of data with DER-encoding of the object identifier indicating the data object type of GOST 28147-89</param>
        /// <param name='pUKM'>pointer to a data with UKM. If pointer takes NULL_PTR value in C_WrapKey operation then random value of UKM will be used.If pointer takes non-NULL_PTR value in C_UnwrapKey operation then the pointer value will be compared with UKM value of wrapped key.If these two values do not match the wrapped key will be rejected</param>
        public CkGOST3410KeyWrapParams(ObjectHandle hKey, byte[] pUKM, byte[] pWrapOID)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
               

                if (Platform.StructPackingSize == 0)
                    _params40 = new HighLevelAPI40.MechanismParams.CkGOST3410KeyWrapParams(hKey.ObjectHandle40, pWrapOID, pUKM);
                else
                    _params41 = new HighLevelAPI41.MechanismParams.CkGOST3410KeyWrapParams(hKey.ObjectHandle41, pWrapOID, pUKM);
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _params80 = new HighLevelAPI80.MechanismParams.CkGOST3410KeyWrapParams(hKey.ObjectHandle80, pWrapOID, pUKM);
                else
                    _params81 = new HighLevelAPI81.MechanismParams.CkGOST3410KeyWrapParams(hKey.ObjectHandle81, pWrapOID, pUKM);
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

            if (Platform.UnmanagedLongSize == 4)
                return (Platform.StructPackingSize == 0) ? _params40.ToMarshalableStructure() : _params41.ToMarshalableStructure();
            else
                return (Platform.StructPackingSize == 0) ? _params80.ToMarshalableStructure() : _params81.ToMarshalableStructure();
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
                    if (_params40 != null)
                    {
                        _params40.Dispose();
                        _params40 = null;
                    }

                    if (_params41 != null)
                    {
                        _params41.Dispose();
                        _params41 = null;
                    }

                    if (_params80 != null)
                    {
                        _params80.Dispose();
                        _params80 = null;
                    }

                    if (_params81 != null)
                    {
                        _params81.Dispose();
                        _params81 = null;
                    }
                }

                // Dispose unmanaged objects

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
