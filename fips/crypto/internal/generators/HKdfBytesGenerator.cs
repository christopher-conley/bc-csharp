using System;

using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Internal.Macs;

namespace Org.BouncyCastle.Crypto.Internal.Generators
{
    /**
     * HMAC-based Extract-and-Expand Key Derivation Function (HKDF) implemented
     * according to IETF RFC 5869, May 2010 as specified by H. Krawczyk, IBM
     * Research &amp; P. Eronen, Nokia. It uses a HMac internally to compute de OKM
     * (output keying material) and is likely to have better security properties
     * than KDF's based on just a hash function.
     */
    internal class HKdfBytesGenerator
        : IDerivationFunction
    {
        private HMac hMacHash;
        private int hashLen;

        private byte[] info;
        private byte[] currentT;

        private int generatedBytes;

        /**
         * Creates a HKDFBytesGenerator based on the given hash function.
         *
         * @param hash the digest to be used as the source of generatedBytes bytes
         */
        public HKdfBytesGenerator(IDigest hash)
        {
            this.hMacHash = new HMac(hash);
            this.hashLen = hash.GetDigestSize();
        }

        public HKdfBytesGenerator(IMac hmac)
        {
            this.hMacHash = (HMac)hmac;
            this.hashLen = hMacHash.GetUnderlyingDigest().GetDigestSize();
        }

        public virtual void Init(IDerivationParameters parameters)
        {
            if (!(parameters is HKdfParameters))
                throw new ArgumentException("HKDF parameters required for HkdfBytesGenerator", "parameters");

            HKdfParameters hkdfParameters = (HKdfParameters)parameters;
  
            hMacHash.Init(hkdfParameters.Key);

            info = hkdfParameters.GetInfo();

            generatedBytes = 0;
            currentT = new byte[hashLen];
        }

        /**
         * Performs the expand part of the key derivation function, using currentT
         * as input and output buffer.
         *
         * @throws DataLengthException if the total number of bytes generated is larger than the one
         * specified by RFC 5869 (255 * HashLen)
         */
        private void ExpandNext()
        {
            int n = generatedBytes / hashLen + 1;
            if (n >= 256)
            {
                throw new DataLengthException(
                    "HKDF cannot generate more than 255 blocks of HashLen size");
            }
            // special case for T(0): T(0) is empty, so no update
            if (generatedBytes != 0)
            {
                hMacHash.BlockUpdate(currentT, 0, hashLen);
            }
            hMacHash.BlockUpdate(info, 0, info.Length);
            hMacHash.Update((byte)n);
            hMacHash.DoFinal(currentT, 0);
        }

        public virtual IDigest Digest
        {
            get { return hMacHash.GetUnderlyingDigest(); }
        }

        public virtual int GenerateBytes(byte[] output, int outOff, int len)
        {
            if (generatedBytes + len > 255 * hashLen)
            {
                throw new DataLengthException(
                    "HKDF may only be used for 255 * HashLen bytes of output");
            }

            if (generatedBytes % hashLen == 0)
            {
                ExpandNext();
            }

            // copy what is left in the currentT (1..hash
            int toGenerate = len;
            int posInT = generatedBytes % hashLen;
            int leftInT = hashLen - generatedBytes % hashLen;
            int toCopy = System.Math.Min(leftInT, toGenerate);
            Array.Copy(currentT, posInT, output, outOff, toCopy);
            generatedBytes += toCopy;
            toGenerate -= toCopy;
            outOff += toCopy;

            while (toGenerate > 0)
            {
                ExpandNext();
                toCopy = System.Math.Min(hashLen, toGenerate);
                Array.Copy(currentT, 0, output, outOff, toCopy);
                generatedBytes += toCopy;
                toGenerate -= toCopy;
                outOff += toCopy;
            }

            return len;
        }
    }
}
