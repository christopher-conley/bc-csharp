using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsRsaEncryptor
        : TlsEncryptor
    {
        private readonly BcTlsCrypto m_crypto;
        private readonly AsymmetricRsaPublicKey m_pubKeyRsa;

        internal BcTlsRsaEncryptor(BcTlsCrypto crypto, AsymmetricRsaPublicKey pubKeyRsa)
        {
            if (pubKeyRsa == null)
                throw new ArgumentNullException("pubKeyRsa");

            this.m_crypto = crypto;
            this.m_pubKeyRsa = pubKeyRsa;
        }

        public byte[] Encrypt(byte[] input)
        {
            IPublicKeyRsaService service = CryptoServicesRegistrar.CreateService(m_pubKeyRsa, m_crypto.SecureRandom);
            IKeyWrapper<Rsa.Pkcs1v15WrapParameters> encryptor = service.CreateKeyWrapper(Rsa.WrapPkcs1v15);
            return encryptor.Wrap(input).Collect();
        }
    }
}
