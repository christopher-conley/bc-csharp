using System;

using Org.BouncyCastle.Crypto.Asymmetric;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Support class for ephemeral Elliptic Curve Diffie-Hellman using the BC light-weight library.</summary>
    public class BcTlsECDH
        : TlsAgreement
    {
        protected readonly BcTlsECDomain m_domain;

        protected AsymmetricKeyPair<AsymmetricECPublicKey, AsymmetricECPrivateKey> m_localKeyPair;
        protected AsymmetricECPublicKey m_peerPublicKey;

        public BcTlsECDH(BcTlsECDomain domain)
        {
            this.m_domain = domain;
        }

        public virtual byte[] GenerateEphemeral()
        {
            this.m_localKeyPair = m_domain.GenerateKeyPair();

            return m_domain.EncodePublicKey(m_localKeyPair.PublicKey);
        }

        public virtual void ReceivePeerValue(byte[] peerValue)
        {
            this.m_peerPublicKey = m_domain.DecodePublicKey(peerValue);
        }

        public virtual TlsSecret CalculateSecret()
        {
            return m_domain.CalculateECDHAgreement(m_localKeyPair.PrivateKey, m_peerPublicKey);
        }
    }
}
