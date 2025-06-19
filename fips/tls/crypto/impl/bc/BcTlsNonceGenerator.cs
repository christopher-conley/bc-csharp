using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsNonceGenerator
        : TlsNonceGenerator
    {
        private readonly SecureRandom m_randomGenerator;

        internal BcTlsNonceGenerator(SecureRandom randomGenerator)
        {
            this.m_randomGenerator = randomGenerator;
        }

        public byte[] GenerateNonce(int size)
        {
            byte[] nonce = new byte[size];
            m_randomGenerator.NextBytes(nonce);
            return nonce;
        }
    }
}
