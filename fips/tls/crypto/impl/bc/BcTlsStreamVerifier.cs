using System;
using System.IO;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsStreamVerifier
        : TlsStreamVerifier
    {
        private readonly IStreamCalculator<IVerifier> m_verifier;
        private readonly byte[] m_signature;

        internal BcTlsStreamVerifier(IStreamCalculator<IVerifier> verifier, byte[] signature)
        {
            this.m_verifier = verifier;
            this.m_signature = signature;
        }

        public Stream Stream
        {
            get { return m_verifier.Stream; }
        }

        public bool IsVerified()
        {
            return BcTlsCrypto.IsVerifiedResult(m_verifier, m_signature);
        }
    }
}
