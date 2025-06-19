using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsECDsa13Signer
        : BcTlsSigner<AsymmetricECPrivateKey>
    {
        private readonly int m_signatureScheme;

        public BcTlsECDsa13Signer(BcTlsCrypto crypto, AsymmetricECPrivateKey privateKey, int signatureScheme)
            : base(crypto, privateKey)
        {
            if (!SignatureScheme.IsECDsa(signatureScheme))
                throw new ArgumentException("signatureScheme");

            this.m_signatureScheme = signatureScheme;
        }

        public override byte[] GenerateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        {
            if (algorithm == null || SignatureScheme.From(algorithm) != m_signatureScheme)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            // TODO[tls-fips] Deterministic DSA not available in approved mode?
            //int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(m_signatureScheme);

            // TODO[tls-fips] Check that null digest is working
            ISignatureFactoryService service = CryptoServicesRegistrar.CreateService(m_privateKey,
                m_crypto.SecureRandom);
            ISignatureFactory<FipsEC.SignatureParameters> signatureFactory = service.CreateSignatureFactory(
                FipsEC.Dsa.WithDigest(null));
            IStreamCalculator<IBlockResult> signer = signatureFactory.CreateCalculator();

            signer.Stream.Write(hash, 0, hash.Length);

            return BcTlsCrypto.CollectResult(signer);
        }
    }
}
