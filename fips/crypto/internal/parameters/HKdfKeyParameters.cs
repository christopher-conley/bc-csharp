using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    /**
     * Parameter class for the HKDFKeyGenerator class.
     */
    internal class HKdfKeyParameters
    {
        private readonly byte[] ikm;
        private readonly bool skipExpand;
        private readonly byte[] salt;

        public HKdfKeyParameters(byte[] ikm, bool skip, byte[] salt)
        {
            if (ikm == null)
            {
                throw new ArgumentException(
                    "IKM (input keying material) should not be null");
            }

            this.ikm = (byte[])ikm.Clone();

            this.skipExpand = skip;

            if (salt == null || salt.Length == 0)
            {
                this.salt = null;
            }
            else
            {
                this.salt = (byte[])salt.Clone();
            }
        }

        /**
         * Returns the input keying material or seed.
         *
         * @return the keying material
         */
        public byte[] GetIKM()
        {
            return Arrays.Clone(ikm);
        }

        /**
         * Returns if step 1: extract has to be skipped or not
         *
         * @return true for skipping, false for no skipping of step 1
         */
        public bool SkipExtract()
        {
            return skipExpand;
        }

        /**
         * Returns the salt, or null if the salt should be generated as a byte array
         * of HashLen zeros.
         *
         * @return the salt, or null
         */
        public byte[] GetSalt()
        {
            return Arrays.Clone(salt);
        }
    }
}
