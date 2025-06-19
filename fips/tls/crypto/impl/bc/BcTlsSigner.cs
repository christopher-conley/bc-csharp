using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public abstract class BcTlsSigner<TPrivateKey>
        : TlsSigner
        where TPrivateKey : IAsymmetricPrivateKey
    {
        protected readonly BcTlsCrypto m_crypto;
        protected readonly TPrivateKey m_privateKey;

        protected BcTlsSigner(BcTlsCrypto crypto, TPrivateKey privateKey)
        {
            if (crypto == null)
                throw new ArgumentNullException("crypto");
            if (privateKey == null)
                throw new ArgumentNullException("privateKey");

            this.m_crypto = crypto;
            this.m_privateKey = privateKey;
        }

        public virtual byte[] GenerateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        {
            throw new NotSupportedException();
        }

        public virtual TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            return null;
        }
    }
}
