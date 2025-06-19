using System;
using System.Collections;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>Base class for a TlsCrypto implementation that provides some needed methods from elsewhere in the impl
    /// package.</summary>
    public abstract class AbstractTlsCrypto
        : TlsCrypto
    {
        public abstract bool HasAnyStreamVerifiers(IList signatureAndHashAlgorithms);

        public abstract bool HasAnyStreamVerifiersLegacy(short[] clientCertificateTypes);

        public abstract bool HasCryptoHashAlgorithm(int cryptoHashAlgorithm);

        public abstract bool HasCryptoSignatureAlgorithm(int cryptoSignatureAlgorithm);

        public abstract bool HasDHAgreement();

        public abstract bool HasECDHAgreement();

        public abstract bool HasEncryptionAlgorithm(int encryptionAlgorithm);

        public abstract bool HasHkdfAlgorithm(int cryptoHashAlgorithm);

        public abstract bool HasMacAlgorithm(int macAlgorithm);

        public abstract bool HasNamedGroup(int namedGroup);

        public abstract bool HasRsaEncryption();

        public abstract bool HasSignatureAlgorithm(short signatureAlgorithm);

        public abstract bool HasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm);

        public abstract bool HasSignatureScheme(int signatureScheme);

        public abstract TlsSecret CreateSecret(byte[] data);

        public abstract TlsSecret GenerateRsaPreMasterSecret(ProtocolVersion clientVersion);

        public abstract SecureRandom SecureRandom { get; }

        public abstract TlsCertificate CreateCertificate(byte[] encoding);

        public abstract TlsCipher CreateCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm);

        public abstract TlsDHDomain CreateDHDomain(TlsDHConfig dhConfig);

        public abstract TlsECDomain CreateECDomain(TlsECConfig ecConfig);

        public virtual TlsSecret AdoptSecret(TlsSecret secret)
        {
            // TODO[tls] Need an alternative that doesn't require AbstractTlsSecret (which holds literal data)
            if (secret is AbstractTlsSecret)
            {
                AbstractTlsSecret sec = (AbstractTlsSecret)secret;

                return CreateSecret(sec.CopyData());
            }

            throw new ArgumentException("unrecognized TlsSecret - cannot copy data: " + Core.Platform.GetTypeName(secret));
        }

        public abstract TlsHash CreateHash(int cryptoHashAlgorithm);

        public abstract TlsHmac CreateHmac(int macAlgorithm);

        public abstract TlsHmac CreateHmacForHash(int cryptoHashAlgorithm);

        public abstract TlsNonceGenerator CreateNonceGenerator(byte[] additionalSeedMaterial);

        public abstract TlsSecret HkdfInit(int cryptoHashAlgorithm);
    }
}
