using System;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    /**
     * Parameter class for the HKDFBytesGenerator class.
     */
    internal class HKDFParameters: IDerivationParameters
    {
        private readonly KeyParameter hkdfKey;
        private readonly byte[] info;

        public HKDFParameters(KeyParameter hkdfKey, byte[] info)
        {
            if (hkdfKey == null)
            {
                throw new ArgumentException(
                "hkdfKey (input keying material) should not be null");
            }

            this.hkdfKey = hkdfKey;

            if (info == null)
            {
                this.info = new byte[0];
            }
            else
            {
                this.info = (byte[])info.Clone();
            }
        }

        /**
         * Returns the input keying material or seed.
         *
         * @return the keying material
         */
        public KeyParameter GetKey()
        {
            return hkdfKey;
        }

        /**
         * Returns the info field, which may be empty (null is converted to empty).
         *
         * @return the info field, never null
         */
        public byte[] GetInfo()
        {
            return (byte[])info.Clone();
        }
    }
}
