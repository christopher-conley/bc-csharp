using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    /**
     * Parameter class for the HKdfBytesGenerator class.
     */
    internal class HKdfParameters
        : IDerivationParameters
    {
        private readonly KeyParameter hkdfKey;
        private readonly byte[] info;

        internal HKdfParameters(KeyParameter hkdfKey, byte[] info)
        {
            this.hkdfKey = hkdfKey;

            if (info == null)
            {
                this.info = new byte[0];
            }
            else
            {
                this.info = Arrays.Clone(info);
            }
        }

        /**
         * Returns the key
         *
         * @return the key.
         */
        public virtual KeyParameter Key
        {
            get { return hkdfKey; }
        }

        /**
         * Returns the info field, which may be empty (null is converted to empty).
         *
         * @return the info field, never null
         */
        public virtual byte[] GetInfo()
        {
            return Arrays.Clone(info);
        }
    }
}
