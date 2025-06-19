using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsEd25519Signer
        : BcTlsSigner<AsymmetricEdDsaPrivateKey>
    {
        public BcTlsEd25519Signer(BcTlsCrypto crypto, AsymmetricEdDsaPrivateKey privateKey)
            : base(crypto, privateKey)
        {
            if (!privateKey.Algorithm.Equals(EdEC.Algorithm.Ed25519))
                throw new ArgumentException("privateKey");
        }

        public override TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            if (algorithm == null || SignatureScheme.From(algorithm) != SignatureScheme.ed25519)
                throw new InvalidOperationException("Invalid algorithm: " + algorithm);

            IPrivateKeyEdDsaService service = CryptoServicesRegistrar.CreateService(m_privateKey);
            ISignatureFactory<EdEC.Parameters> signatureFactory = service.CreateSignatureFactory(EdEC.Ed25519);
            IStreamCalculator<IBlockResult> signer = signatureFactory.CreateCalculator();

            return new BcTlsStreamSigner(signer);
        }
    }
}
