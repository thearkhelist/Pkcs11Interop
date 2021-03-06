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
    /// Type, value and length of an OTP parameter
    /// </summary>
    public class CkOtpParam : IMechanismParams, IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;
        
        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private LowLevelAPI.MechanismParams.CK_OTP_PARAM _lowLevelStruct = new LowLevelAPI.MechanismParams.CK_OTP_PARAM();

        /// <summary>
        /// Parameter type
        /// </summary>
        public uint Type
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _lowLevelStruct.Type;
            }
        }

        /// <summary>
        /// Value of the parameter
        /// </summary>
        public byte[] Value
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return (_lowLevelStruct.Value == IntPtr.Zero) ? null : LowLevelAPI.UnmanagedMemory.Read(_lowLevelStruct.Value, (int)_lowLevelStruct.ValueLen);
            }
        }

        /// <summary>
        /// Initializes a new instance of the CkOtpParam class.
        /// </summary>
        /// <param name='type'>Parameter type</param>
        /// <param name='value'>Value of the parameter</param>
        public CkOtpParam(uint type, byte[] value)
        {
            _lowLevelStruct.Type = 0;
            _lowLevelStruct.Value = IntPtr.Zero;
            _lowLevelStruct.ValueLen = 0;

            _lowLevelStruct.Type = type;

            if (value != null)
            {
                _lowLevelStruct.Value = LowLevelAPI.UnmanagedMemory.Allocate(value.Length);
                LowLevelAPI.UnmanagedMemory.Write(_lowLevelStruct.Value, value);
                _lowLevelStruct.ValueLen = (uint)value.Length;
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
                LowLevelAPI.UnmanagedMemory.Free(ref _lowLevelStruct.Value);
                _lowLevelStruct.ValueLen = 0;

                _disposed = true;
            }
        }
        
        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~CkOtpParam()
        {
            Dispose(false);
        }
        
        #endregion
    }
}
