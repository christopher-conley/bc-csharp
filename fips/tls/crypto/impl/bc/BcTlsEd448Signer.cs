using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsEd448Signer
        : BcTlsSigner<AsymmetricEdDsaPrivateKey>
    {
        public BcTlsEd448Signer(BcTlsCrypto crypto, AsymmetricEdDsaPrivateKey privateKey)
            : base(crypto, privateKey)
        {
            if (!privateKey.Algorithm.Equals(EdEC.Algorithm.Ed448))
                throw new ArgumentException("privateKey");
        }

        public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            if (algorithm == null || SignatureScheme.From(algorithm) != SignatureScheme.ed448)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            IPrivateKeyEdDsaService service = CryptoServicesRegistrar.CreateService(m_privateKey);
            ISignatureFactory<EdEC.Parameters> signatureFactory = service.CreateSignatureFactory(EdEC.Ed448);
            IStreamCalculator<IBlockResult> signer = signatureFactory.CreateCalculator();

            return new BcTlsStreamSigner(signer);
        }
    }
}
