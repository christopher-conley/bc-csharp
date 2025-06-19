using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsRsaVerifier
        : BcTlsVerifier<AsymmetricRsaPublicKey>
    {
        public BcTlsRsaVerifier(BcTlsCrypto crypto, AsymmetricRsaPublicKey publicKey)
            : base(crypto, publicKey)
        {
        }

        public override bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash)
        {
            throw new NotSupportedException();

            // TODO[tls-fips] Support for null digest (raw)
            // TODO[tls-fips] Needs to know the hash OID? (TlsUtilities.GetOidForHashAlgorithm(algorithm.Hash))

            //SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;

            //if (algorithm == null)
            //{
            //    /*
            //     * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
            //     * that did not include a DigestInfo encoding.
            //     */
            //    //signer = new GenericSigner(new Pkcs1Encoding(new RsaBlindedEngine()), nullDigest);
            //    throw new NotImplementedException();
            //}

            //if (algorithm.Signature != SignatureAlgorithm.rsa)
            //    throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            ///*
            // * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
            // * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
            // */
            //// TODO[tls-fips] Check that null digest is working
            //// TODO[tls-fips] Needs to know the hash OID? (TlsUtilities.GetOidForHashAlgorithm(algorithm.Hash))
            //IVerifierFactoryService service = CryptoServicesRegistrar.CreateService(m_publicKey);
            //IVerifierFactory<FipsRsa.SignatureParameters> verifierFactory = service.CreateVerifierFactory(
            //    FipsRsa.Pkcs1v15.WithDigest(null));
            //IStreamCalculator<IVerifier> verifier = verifierFactory.CreateCalculator();

            //verifier.Stream.Write(hash, 0, hash.Length);

            //return BcTlsCrypto.IsVerifiedResult(verifier, digitallySigned.Signature);
        }

        public override TlsStreamVerifier GetStreamVerifier(DigitallySigned digitallySigned)
        {
            SignatureAndHashAlgorithm algorithm = digitallySigned.Algorithm;

            if (algorithm == null)
            {
                /*
                 * RFC 5246 4.7. Note that earlier versions of TLS used a different RSA signature scheme
                 * that did not include a DigestInfo encoding.
                 */
                //signer = new GenericSigner(new Pkcs1Encoding(new RsaBlindedEngine()), nullDigest);
                throw new NotImplementedException();
            }

            if (algorithm.Signature != SignatureAlgorithm.rsa)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            int cryptoHashAlgorithm = TlsCryptoUtilities.GetHash(algorithm.Hash);
            FipsShs.Parameters digestParameters = m_crypto.GetDigestParameters(cryptoHashAlgorithm);

            IStreamCalculator<IVerifier> verifier = CreateVerifier(m_crypto, m_publicKey, digestParameters);

            return new BcTlsStreamVerifier(verifier, digitallySigned.Signature);
        }

        internal static IStreamCalculator<IVerifier> CreateVerifier(BcTlsCrypto crypto,
            AsymmetricRsaPublicKey publicKey, FipsShs.Parameters digestParameters)
        {
            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */
            IVerifierFactoryService service = CryptoServicesRegistrar.CreateService(publicKey);
            IVerifierFactory<FipsRsa.SignatureParameters> verifierFactory = service.CreateVerifierFactory(
                FipsRsa.Pkcs1v15.WithDigest(digestParameters));
            return verifierFactory.CreateCalculator();
        }
    }
}
