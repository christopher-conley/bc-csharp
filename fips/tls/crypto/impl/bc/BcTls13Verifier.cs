using System;
using System.IO;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTls13Verifier
        : Tls13Verifier
    {
        private readonly IStreamCalculator<IVerifier> m_verifier;

        internal BcTls13Verifier(IStreamCalculator<IVerifier> verifier)
        {
            if (verifier == null)
                throw new ArgumentNullException("verifier");

            this.m_verifier = verifier;
        }

        public Stream Stream
        {
            get { return m_verifier.Stream; }
        }

        public bool VerifySignature(byte[] signature)
        {
            return BcTlsCrypto.IsVerifiedResult(m_verifier, signature);
        }
    }
}
