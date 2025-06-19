using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsECDsaVerifier
        : BcTlsVerifier<AsymmetricECPublicKey>
    {
        public BcTlsECDsaVerifier(BcTlsCrypto crypto, AsymmetricECPublicKey publicKey)
            : base(crypto, publicKey)
        {
        }

        public override bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
        {
            SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
            if (algorithm != null && algorithm.Signature != SignatureAlgorithm.ecdsa)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            IVerifierFactoryService service = CryptoServicesRegistrar.CreateService(m_publicKey);
            IVerifierFactory<FipsEC.SignatureParameters> verifierFactory = service.CreateVerifierFactory(
                FipsEC.Dsa.WithDigest(null));
            IStreamCalculator<IVerifier> verifier = verifierFactory.CreateCalculator();

            if (algorithm == null)
            {
                // Note: Only use the SHA1 part of the (MD5/SHA1) hash
                verifier.Stream.Write(hash, 16, 20);
            }
            else
            {
                verifier.Stream.Write(hash, 0, hash.Length);
            }

            return BcTlsCrypto.IsVerifiedResult(verifier, digitallySigned.Signature);
        }
    }
}
