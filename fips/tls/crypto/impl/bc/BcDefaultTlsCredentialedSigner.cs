using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.General;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Credentialed class for generating signatures based on the use of primitives from the BC light-weight API.</summary>
    public class BcDefaultTlsCredentialedSigner
        : DefaultTlsCredentialedSigner
    {
        private static BcTlsCertificate GetEndEntity(BcTlsCrypto crypto, Certificate certificate)
        {
            if (certificate == null || certificate.IsEmpty)
                throw new ArgumentException("No certificate");

            return BcTlsCertificate.Convert(crypto, certificate.GetCertificateAt(0));
        }

        private static TlsSigner MakeSigner(BcTlsCrypto crypto, IAsymmetricPrivateKey privateKey,
            Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm)
        {
            TlsSigner signer;
            if (privateKey is AsymmetricRsaPrivateKey)
            {
                AsymmetricRsaPrivateKey privKeyRsa = (AsymmetricRsaPrivateKey)privateKey;

                if (signatureAndHashAlgorithm != null)
                {
                    int signatureScheme = SignatureScheme.From(signatureAndHashAlgorithm);
                    if (SignatureScheme.IsRsaPss(signatureScheme))
                    {
                        return new BcTlsRsaPssSigner(crypto, privKeyRsa, signatureScheme);
                    }
                }

                AsymmetricRsaPublicKey pubKeyRsa = GetEndEntity(crypto, certificate).GetPubKeyRsa();

                signer = new BcTlsRsaSigner(crypto, privKeyRsa, pubKeyRsa);
            }
            else if (privateKey is AsymmetricDsaPrivateKey)
            {
                signer = new BcTlsDsaSigner(crypto, (AsymmetricDsaPrivateKey)privateKey);
            }
            else if (privateKey is AsymmetricECPrivateKey)
            {
                AsymmetricECPrivateKey privKeyEC = (AsymmetricECPrivateKey)privateKey;

                if (signatureAndHashAlgorithm != null)
                {
                    int signatureScheme = SignatureScheme.From(signatureAndHashAlgorithm);
                    if (SignatureScheme.IsECDsa(signatureScheme))
                    {
                        return new BcTlsECDsa13Signer(crypto, privKeyEC, signatureScheme);
                    }
                }

                signer = new BcTlsECDsaSigner(crypto, privKeyEC);
            }
            else if (privateKey is AsymmetricEdDsaPrivateKey)
            {
                AsymmetricEdDsaPrivateKey privKeyEdDsa = (AsymmetricEdDsaPrivateKey)privateKey;

                Algorithm algorithm = privKeyEdDsa.Algorithm;
                if (algorithm.Equals(EdEC.Algorithm.Ed25519))
                {
                    signer = new BcTlsEd25519Signer(crypto, privKeyEdDsa);
                }
                else if (algorithm.Equals(EdEC.Algorithm.Ed448))
                {
                    signer = new BcTlsEd448Signer(crypto, privKeyEdDsa);
                }
                else
                {
                    throw new ArgumentException("EdEC algorithm not supported: " + algorithm.Name);
                }
            }
            else
            {
                throw new ArgumentException("'privateKey' type not supported: " + Core.Platform.GetTypeName(privateKey));
            }

            return signer;
        }

        public BcDefaultTlsCredentialedSigner(TlsCryptoParameters cryptoParams, BcTlsCrypto crypto,
            IAsymmetricPrivateKey privateKey, Certificate certificate,
            SignatureAndHashAlgorithm signatureAndHashAlgorithm)
            : base(cryptoParams, MakeSigner(crypto, privateKey, certificate, signatureAndHashAlgorithm), certificate,
                signatureAndHashAlgorithm)
        {
        }
    }
}
