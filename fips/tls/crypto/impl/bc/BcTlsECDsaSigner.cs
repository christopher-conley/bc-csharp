using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsECDsaSigner
         : BcTlsSigner<AsymmetricECPrivateKey>
    {
        public BcTlsECDsaSigner(BcTlsCrypto crypto, AsymmetricECPrivateKey privateKey)
            : base(crypto, privateKey)
        {
        }

        public override byte[] GenerateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        {
            if (algorithm != null && algorithm.Signature != SignatureAlgorithm.ecdsa)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            // TODO[tls-fips] Deterministic DSA not available in approved mode?
            //int cryptoHashAlgorithm = (null == algorithm)
            //    ? CryptoHashAlgorithm.sha1
            //    : TlsCryptoUtilities.GetHash(algorithm.Hash);

            // TODO[tls-fips] Check that null digest is working
            ISignatureFactoryService service = CryptoServicesRegistrar.CreateService(m_privateKey,
                m_crypto.SecureRandom);
            ISignatureFactory<FipsEC.SignatureParameters> signatureFactory = service.CreateSignatureFactory(
                FipsEC.Dsa.WithDigest(null));
            IStreamCalculator<IBlockResult> signer = signatureFactory.CreateCalculator();

            if (algorithm == null)
            {
                // Note: Only use the SHA1 part of the (MD5/SHA1) hash
                signer.Stream.Write(hash, 16, 20);
            }
            else
            {
                signer.Stream.Write(hash, 0, hash.Length);
            }

            return BcTlsCrypto.CollectResult(signer);
        }
    }
}
