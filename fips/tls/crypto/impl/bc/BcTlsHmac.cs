using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsHmac
        : TlsHmac
    {
        private readonly FipsShs.AuthenticationParameters m_parameterSet;
        private readonly int m_internalBlockSize;

        private IStreamCalculator<IBlockResult> m_hmac;

        internal BcTlsHmac(BcTlsCrypto crypto, int cryptoHashAlgorithm)
        {
            this.m_parameterSet = crypto.GetHmacParameters(cryptoHashAlgorithm);
            this.m_internalBlockSize = TlsCryptoUtilities.GetHashInternalSize(cryptoHashAlgorithm);
        }

        public void SetKey(byte[] key, int keyOff, int keyLen)
        {
            FipsShs.Key serviceKey = new FipsShs.Key(m_parameterSet, Arrays.CopyOfRange(key, keyOff, keyOff + keyLen));
            this.m_hmac = CryptoServicesRegistrar
                .CreateService(serviceKey)
                .CreateMacFactory(m_parameterSet)
                .CreateCalculator();
        }

        public void Update(byte[] input, int inOff, int length)
        {
            m_hmac.Stream.Write(input, inOff, length);
        }

        public byte[] CalculateMac()
        {
            m_hmac.Stream.Close();
            return m_hmac.GetResult().Collect();
        }

        public void CalculateMac(byte[] output, int outOff)
        {
            m_hmac.Stream.Close();
            m_hmac.GetResult().Collect(output, outOff);
        }

        public int InternalBlockSize
        {
            get { return m_internalBlockSize; }
        }

        public int MacLength
        {
            get { return (m_parameterSet.MacSizeInBits + 7) / 8; }
        }

        public void Reset()
        {
            CalculateMac();
        }
    }
}
