using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsRsaSigner
        : BcTlsSigner<AsymmetricRsaPrivateKey>
    {
        private readonly AsymmetricRsaPublicKey m_publicKey;

        public BcTlsRsaSigner(BcTlsCrypto crypto, AsymmetricRsaPrivateKey privateKey, AsymmetricRsaPublicKey publicKey)
            : base(crypto, privateKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException("publicKey");

            this.m_publicKey = publicKey;
        }

        public override byte[] GenerateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        {
            throw new NotSupportedException();

            // TODO[tls-fips] Support for null digest (raw)
            // TODO[tls-fips] Needs to know the hash OID? (TlsUtilities.GetOidForHashAlgorithm(algorithm.Hash))

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
            //ISignatureFactoryService service = CryptoServicesRegistrar.CreateService(m_privateKey,
            //    m_crypto.SecureRandom);
            //ISignatureFactory<FipsRsa.SignatureParameters> signatureFactory = service.CreateSignatureFactory(
            //    FipsRsa.Pkcs1v15.WithDigest(null));
            //IStreamCalculator<IBlockResult> signer = signatureFactory.CreateCalculator();

            //signer.Stream.Write(hash, 0, hash.Length);

            //byte[] signature = BcTlsCrypto.CollectResult(signer);

            //BcTlsRsaVerifier verifier = new BcTlsRsaVerifier(m_crypto, m_publicKey);
            //if (!verifier.VerifyRawSignature(new DigitallySigned(algorithm, signature), hash))
            //    throw new TlsFatalAlert(AlertDescription.internal_error);

            //return signature;
        }

        public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
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

            /*
             * RFC 5246 4.7. In RSA signing, the opaque vector contains the signature generated
             * using the RSASSA-PKCS1-v1_5 signature scheme defined in [PKCS1].
             */
            ISignatureFactoryService service = CryptoServicesRegistrar.CreateService(m_privateKey,
                m_crypto.SecureRandom);
            ISignatureFactory<FipsRsa.SignatureParameters> signatureFactory = service.CreateSignatureFactory(
                FipsRsa.Pkcs1v15.WithDigest(digestParameters));
            IStreamCalculator<IBlockResult> signer = signatureFactory.CreateCalculator();

            IStreamCalculator<IVerifier> verifier = BcTlsRsaVerifier.CreateVerifier(m_crypto, m_publicKey,
                digestParameters);

            return new BcVerifyingStreamSigner(signer, verifier);
        }
    }
}
