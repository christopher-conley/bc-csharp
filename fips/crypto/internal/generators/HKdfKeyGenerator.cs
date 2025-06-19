using System;

using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Internal.Generators
{
    /**
     * Key Generator for HMAC-based Extract-and-Expand Key Derivation Function (HKDF) implemented
     * according to IETF RFC 5869, May 2010 as specified by H. Krawczyk, IBM
     * Research &amp; P. Eronen, Nokia. It uses a HMac internally to compute de OKM
     * (output keying material) and is likely to have better security properties
     * than KDF's based on just a hash function.
     */
    internal class HKdfKeyGenerator
    {
        private HMac hMacHash;
        private int hashLen;

        /**
         * Creates a HKDFBytesGenerator based on the given hash function.
         *
         * @param hash the digest to be used as the source of generatedBytes bytes
         */
        public HKdfKeyGenerator(IDigest hash)
        {
            this.hMacHash = new HMac(hash);
            this.hashLen = hash.GetDigestSize();
        }

        public HKdfKeyGenerator(HMac hMac)
        {
            this.hMacHash = hMac;
            this.hashLen = hMac.GetUnderlyingDigest().GetDigestSize();
        }

        public KeyParameter Generate(HKdfKeyParameters parameters)
        {
            if (parameters.SkipExtract())
            {
                // use IKM directly as PRK
                return new KeyParameter(parameters.GetIKM());
            }
            else
            {
                return extract(parameters.GetSalt(), parameters.GetIKM());
            }
        }

        /**
         * Performs the extract part of the key derivation function.
         *
         * @param salt the salt to use
         * @param ikm  the input keying material
         * @return the PRK as KeyParameter
         */
        private KeyParameter extract(byte[] salt, byte[] ikm)
        {
            if (salt == null)
            {
                // TODO check if hashLen is indeed same as HMAC size
                hMacHash.Init(new KeyParameter(new byte[hashLen]));
            }
            else
            {
                hMacHash.Init(new KeyParameter(salt));
            }

            hMacHash.BlockUpdate(ikm, 0, ikm.Length);

            byte[] prk = new byte[hashLen];
            hMacHash.DoFinal(prk, 0);

            return new KeyParameter(prk);
        }
    }
}
