using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public abstract class BcTlsVerifier<TPublicKey>
        : TlsVerifier
        where TPublicKey : IAsymmetricPublicKey
    {
        protected readonly BcTlsCrypto m_crypto;
        protected readonly TPublicKey m_publicKey;

        protected BcTlsVerifier(BcTlsCrypto crypto, TPublicKey publicKey)
        {
            if (crypto == null)
                throw new ArgumentNullException("crypto");
            if (publicKey == null)
                throw new ArgumentNullException("publicKey");

            this.m_crypto = crypto;
            this.m_publicKey = publicKey;
        }

        public virtual TlsStreamVerifier GetStreamVerifier(DigitallySigned digitallySigned)
        {
            return null;
        }

        public virtual bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
        {
            throw new NotSupportedException();
        }
    }
}
