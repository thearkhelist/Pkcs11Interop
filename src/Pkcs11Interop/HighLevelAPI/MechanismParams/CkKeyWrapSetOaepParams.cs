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

namespace Net.Pkcs11Interop.HighLevelAPI.MechanismParams
{
    /// <summary>
    /// Parameters for the CKM_KEY_WRAP_SET_OAEP mechanism
    /// </summary>
    public class CkKeyWrapSetOaepParams : IMechanismParams, IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;
        
        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private LowLevelAPI.MechanismParams.CK_KEY_WRAP_SET_OAEP_PARAMS _lowLevelStruct = new LowLevelAPI.MechanismParams.CK_KEY_WRAP_SET_OAEP_PARAMS();

        /// <summary>
        /// Initializes a new instance of the CkKeyWrapSetOaepParams class.
        /// </summary>
        /// <param name='bc'>Block contents byte</param>
        /// <param name='x'>Concatenation of hash of plaintext data (if present) and extra data (if present)</param>
        public CkKeyWrapSetOaepParams(byte bc, byte[] x)
        {
            _lowLevelStruct.BC = 0;
            _lowLevelStruct.X = IntPtr.Zero;
            _lowLevelStruct.XLen = 0;

            _lowLevelStruct.BC = bc;

            if (x != null)
            {
                _lowLevelStruct.X = LowLevelAPI.UnmanagedMemory.Allocate(x.Length);
                LowLevelAPI.UnmanagedMemory.Write(_lowLevelStruct.X, x);
                _lowLevelStruct.XLen = (uint)x.Length;
            }
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
                LowLevelAPI.UnmanagedMemory.Free(ref _lowLevelStruct.X);
                _lowLevelStruct.XLen = 0;

                _disposed = true;
            }
        }
        
        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~CkKeyWrapSetOaepParams()
        {
            Dispose(false);
        }
        
        #endregion
    }
}
