using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsDsaVerifier
        : BcTlsVerifier<AsymmetricDsaPublicKey>
    {
        public BcTlsDsaVerifier(BcTlsCrypto crypto, AsymmetricDsaPublicKey publicKey)
            : base(crypto, publicKey)
        {
        }

        public override bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
        {
            throw new NotSupportedException();

            // TODO[tls-fips] Support for null digest (raw)

            //SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
            //if (algorithm != null && algorithm.Signature != SignatureAlgorithm.dsa)
            //    throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            //IVerifierFactoryService service = CryptoServicesRegistrar.CreateService(m_publicKey);
            //IVerifierFactory<FipsDsa.SignatureParameters> verifierFactory = service.CreateVerifierFactory(
            //    FipsDsa.Dsa.WithDigest(null));
            //IStreamCalculator<IVerifier> verifier = verifierFactory.CreateCalculator();

            //if (algorithm == null)
            //{
            //    // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            //    verifier.Stream.Write(hash, 16, 20);
            //}
            //else
            //{
            //    verifier.Stream.Write(hash, 0, hash.Length);
            //}

            //return BcTlsCrypto.IsVerifiedResult(verifier, digitallySigned.Signature);
        }

        public override TlsStreamVerifier GetStreamVerifier(DigitallySigned digitallySigned)
        {
            SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;
            if (algorithm != null && algorithm.Signature != SignatureAlgorithm.dsa)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            int cryptoHashAlgorithm = (null == algorithm)
                ? CryptoHashAlgorithm.sha1
                : TlsCryptoUtilities.GetHash(algorithm.Hash);
            FipsShs.Parameters digestParameters = m_crypto.GetDigestParameters(cryptoHashAlgorithm);

            IVerifierFactoryService service = CryptoServicesRegistrar.CreateService(m_publicKey);
            IVerifierFactory<FipsDsa.SignatureParameters> verifierFactory = service.CreateVerifierFactory(
                FipsDsa.Dsa.WithDigest(digestParameters));
            IStreamCalculator<IVerifier> verifier = verifierFactory.CreateCalculator();

            return new BcTlsStreamVerifier(verifier, digitallySigned.Signature);
        }
    }
}
