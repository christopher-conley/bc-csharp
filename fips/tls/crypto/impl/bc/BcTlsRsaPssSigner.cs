using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsRsaPssSigner
        : BcTlsSigner<AsymmetricRsaPrivateKey>
    {
        private readonly int m_signatureScheme;

        public BcTlsRsaPssSigner(BcTlsCrypto crypto, AsymmetricRsaPrivateKey privateKey, int signatureScheme)
            : base(crypto, privateKey)
        {
            if (!SignatureScheme.IsRsaPss(signatureScheme))
                throw new ArgumentException("signatureScheme");

            this.m_signatureScheme = signatureScheme;
        }

        public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            if (algorithm == null || SignatureScheme.From(algorithm) != m_signatureScheme)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(m_signatureScheme);
            FipsShs.Parameters digestParameters = m_crypto.GetDigestParameters(cryptoHashAlgorithm);

            ISignatureFactoryService service = CryptoServicesRegistrar.CreateService(m_privateKey,
                m_crypto.SecureRandom);
            ISignatureFactory<FipsRsa.PssSignatureParameters> signatureFactory = service.CreateSignatureFactory(
                FipsRsa.Pss.WithDigest(digestParameters));
            IStreamCalculator<IBlockResult> signer = signatureFactory.CreateCalculator();

            return new BcTlsStreamSigner(signer);
        }
    }
}
