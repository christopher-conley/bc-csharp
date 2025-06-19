using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsDsaSigner
        : BcTlsSigner<AsymmetricDsaPrivateKey>
    {
        public BcTlsDsaSigner(BcTlsCrypto crypto, AsymmetricDsaPrivateKey privateKey)
            : base(crypto, privateKey)
        {
        }

        public override byte[] GenerateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        {
            throw new NotSupportedException();

            // TODO[tls-fips] Support for null digest (raw)
            // TODO[tls-fips] Deterministic DSA not available in approved mode

            //if (algorithm != null && algorithm.Signature != SignatureAlgorithm.dsa)
            //    throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            //ISignatureFactoryService service = CryptoServicesRegistrar.CreateService(m_privateKey,
            //    m_crypto.SecureRandom);
            //ISignatureFactory<FipsDsa.SignatureParameters> signatureFactory = service.CreateSignatureFactory(
            //    FipsDsa.Dsa.WithDigest(null));
            //IStreamCalculator<IBlockResult> signer = signatureFactory.CreateCalculator();

            //if (algorithm == null)
            //{
            //    // Note: Only use the SHA1 part of the (MD5/SHA1) hash
            //    signer.Stream.Write(hash, 16, 20);
            //}
            //else
            //{
            //    signer.Stream.Write(hash, 0, hash.Length);
            //}

            //return BcTlsCrypto.CollectResult(signer);
        }

        public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            if (algorithm != null && algorithm.Signature != SignatureAlgorithm.dsa)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            int cryptoHashAlgorithm = (null == algorithm)
                ? CryptoHashAlgorithm.sha1
                : TlsCryptoUtilities.GetHash(algorithm.Hash);
            FipsShs.Parameters digestParameters = m_crypto.GetDigestParameters(cryptoHashAlgorithm);

            ISignatureFactoryService service = CryptoServicesRegistrar.CreateService(m_privateKey,
                m_crypto.SecureRandom);
            ISignatureFactory<FipsDsa.SignatureParameters> signatureFactory = service.CreateSignatureFactory(
                FipsDsa.Dsa.WithDigest(digestParameters));
            IStreamCalculator<IBlockResult> signer = signatureFactory.CreateCalculator();

            return new BcTlsStreamSigner(signer);
        }
    }
}
