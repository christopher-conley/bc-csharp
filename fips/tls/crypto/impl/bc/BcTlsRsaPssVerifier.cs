using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsRsaPssVerifier
        : BcTlsVerifier<AsymmetricRsaPublicKey>
    {
        private readonly int m_signatureScheme;

        public BcTlsRsaPssVerifier(BcTlsCrypto crypto, AsymmetricRsaPublicKey publicKey, int signatureScheme)
            : base(crypto, publicKey)
        {
            if (!SignatureScheme.IsRsaPss(signatureScheme))
                throw new ArgumentException("signatureScheme");

            this.m_signatureScheme = signatureScheme;
        }

        public override TlsStreamVerifier GetStreamVerifier(DigitallySigned digitallySigned)
        {
            SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
            if (algorithm == null || SignatureScheme.From(algorithm) != m_signatureScheme)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            IStreamCalculator<IVerifier> verifier = CreateVerifier(m_crypto, m_publicKey, m_signatureScheme);

            return new BcTlsStreamVerifier(verifier, digitallySigned.Signature);
        }

        internal static IStreamCalculator<IVerifier> CreateVerifier(BcTlsCrypto crypto,
            AsymmetricRsaPublicKey publicKey, int signatureScheme)
        {
            int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(signatureScheme);
            FipsShs.Parameters digestParameters = crypto.GetDigestParameters(cryptoHashAlgorithm);

            return CreateVerifier(crypto, publicKey, digestParameters);
        }

        internal static IStreamCalculator<IVerifier> CreateVerifier(BcTlsCrypto crypto,
            AsymmetricRsaPublicKey publicKey, FipsShs.Parameters digestParameters)
        {
            IVerifierFactoryService service = CryptoServicesRegistrar.CreateService(publicKey);
            IVerifierFactory<FipsRsa.PssSignatureParameters> verifierFactory = service.CreateVerifierFactory(
                FipsRsa.Pss.WithDigest(digestParameters));
            return verifierFactory.CreateCalculator();
        }
    }
}
