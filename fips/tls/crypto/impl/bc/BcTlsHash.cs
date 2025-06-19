using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsHash
        : TlsHash
    {
        private readonly BcTlsCrypto m_crypto;
        private readonly int m_cryptoHashAlgorithm;
        private readonly IStreamCalculator<IBlockResult> m_digest;

        internal BcTlsHash(BcTlsCrypto crypto, int cryptoHashAlgorithm)
            : this(crypto, cryptoHashAlgorithm, crypto.CreateDigest(cryptoHashAlgorithm))
        {
        }

        private BcTlsHash(BcTlsCrypto crypto, int cryptoHashAlgorithm, IStreamCalculator<IBlockResult> digest)
        {
            this.m_crypto = crypto;
            this.m_cryptoHashAlgorithm = cryptoHashAlgorithm;
            this.m_digest = digest;
        }

        public void Update(byte[] data, int offSet, int length)
        {
            m_digest.Stream.Write(data, offSet, length);
        }

        public byte[] CalculateHash()
        {
            m_digest.Stream.Close();
            return m_digest.GetResult().Collect();
        }

        public void Reset()
        {
            CalculateHash();
        }
    }
}
