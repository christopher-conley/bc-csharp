using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Implementation class for a single X.509 certificate based on the BC light-weight API.</summary>
    public class BcTlsCertificate
        : TlsCertificate
    {
        /// <exception cref="IOException"/>
        public static BcTlsCertificate Convert(BcTlsCrypto crypto, TlsCertificate certificate)
        {
            if (certificate is BcTlsCertificate)
                return (BcTlsCertificate)certificate;

            return new BcTlsCertificate(crypto, certificate.GetEncoded());
        }

        /// <exception cref="IOException"/>
        public static X509CertificateStructure ParseCertificate(byte[] encoding)
        {
            try
            {
                Asn1Object asn1 = TlsUtilities.ReadAsn1Object(encoding);
                return X509CertificateStructure.GetInstance(asn1);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate, e);
            }
        }

        protected readonly BcTlsCrypto m_crypto;
        protected readonly X509CertificateStructure m_certificate;

        protected AsymmetricDHPublicKey m_pubKeyDH = null;
        protected AsymmetricECPublicKey m_pubKeyEC = null;
        protected AsymmetricEdDsaPublicKey m_pubKeyEd25519 = null;
        protected AsymmetricEdDsaPublicKey m_pubKeyEd448 = null;
        protected AsymmetricRsaPublicKey m_pubKeyRsa = null;

        /// <exception cref="IOException"/>
        public BcTlsCertificate(BcTlsCrypto crypto, byte[] encoding)
            : this(crypto, ParseCertificate(encoding))
        {
        }

        public BcTlsCertificate(BcTlsCrypto crypto, X509CertificateStructure certificate)
        {
            this.m_crypto = crypto;
            this.m_certificate = certificate;
        }

        /// <exception cref="IOException"/>
        public virtual TlsEncryptor CreateEncryptor(int tlsCertificateRole)
        {
            ValidateKeyUsage(KeyUsage.KeyEncipherment);

            switch (tlsCertificateRole)
            {
            case TlsCertificateRole.RsaEncryption:
            {
                this.m_pubKeyRsa = GetPubKeyRsa();
                return new BcTlsRsaEncryptor(m_crypto, m_pubKeyRsa);
            }
            // TODO[gmssl]
            //case TlsCertificateRole.Sm2Encryption:
            //{
            //    this.m_pubKeyEC = GetPubKeyEC();
            //    return new BcTlsSM2Encryptor(m_crypto, m_pubKeyEC);
            //}
            }

            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        public virtual TlsVerifier CreateVerifier(short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.ed25519:
            case SignatureAlgorithm.ed448:
            {
                int signatureScheme = SignatureScheme.From(HashAlgorithm.Intrinsic, signatureAlgorithm);
                Tls13Verifier tls13Verifier = CreateVerifier(signatureScheme);
                return new LegacyTls13Verifier(signatureScheme, tls13Verifier);
            }
            }

            ValidateKeyUsage(KeyUsage.DigitalSignature);

            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.dsa:
                return new BcTlsDsaVerifier(m_crypto, GetPubKeyDss());

            case SignatureAlgorithm.ecdsa:
                return new BcTlsECDsaVerifier(m_crypto, GetPubKeyEC());

            case SignatureAlgorithm.rsa:
            {
                ValidateRsa_Pkcs1();
                return new BcTlsRsaVerifier(m_crypto, GetPubKeyRsa());
            }

            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
            {
                ValidateRsa_Pss_Pss(signatureAlgorithm);
                int signatureScheme = SignatureScheme.From(HashAlgorithm.Intrinsic, signatureAlgorithm);
                return new BcTlsRsaPssVerifier(m_crypto, GetPubKeyRsa(), signatureScheme);
            }

            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
            {
                ValidateRsa_Pss_Rsae();
                int signatureScheme = SignatureScheme.From(HashAlgorithm.Intrinsic, signatureAlgorithm);
                return new BcTlsRsaPssVerifier(m_crypto, GetPubKeyRsa(), signatureScheme);
            }

            default:
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }
        }

        /// <exception cref="IOException"/>
        public virtual Tls13Verifier CreateVerifier(int signatureScheme)
        {
            ValidateKeyUsage(KeyUsage.DigitalSignature);

            switch (signatureScheme)
            {
            case SignatureScheme.ecdsa_brainpoolP256r1tls13_sha256:
            case SignatureScheme.ecdsa_brainpoolP384r1tls13_sha384:
            case SignatureScheme.ecdsa_brainpoolP512r1tls13_sha512:
            case SignatureScheme.ecdsa_secp256r1_sha256:
            case SignatureScheme.ecdsa_secp384r1_sha384:
            case SignatureScheme.ecdsa_secp521r1_sha512:
            case SignatureScheme.ecdsa_sha1:
            {
                int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(signatureScheme);
                FipsShs.Parameters digestParameters = m_crypto.GetDigestParameters(cryptoHashAlgorithm);

                IVerifierFactoryService service = CryptoServicesRegistrar.CreateService(GetPubKeyEC());
                IVerifierFactory<FipsEC.SignatureParameters> verifierFactory = service.CreateVerifierFactory(
                    FipsEC.Dsa.WithDigest(digestParameters));
                IStreamCalculator<IVerifier> verifier = verifierFactory.CreateCalculator();

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.ed25519:
            {
                IVerifierFactoryService service = CryptoServicesRegistrar.CreateService(GetPubKeyEd25519());
                IVerifierFactory<EdEC.Parameters> verifierFactory = service.CreateVerifierFactory(EdEC.Ed25519);
                IStreamCalculator<IVerifier> verifier = verifierFactory.CreateCalculator();

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.ed448:
            {
                IVerifierFactoryService service = CryptoServicesRegistrar.CreateService(GetPubKeyEd448());
                IVerifierFactory<EdEC.Parameters> verifierFactory = service.CreateVerifierFactory(EdEC.Ed448);
                IStreamCalculator<IVerifier> verifier = verifierFactory.CreateCalculator();

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.rsa_pkcs1_sha1:
            case SignatureScheme.rsa_pkcs1_sha256:
            case SignatureScheme.rsa_pkcs1_sha384:
            case SignatureScheme.rsa_pkcs1_sha512:
            {
                ValidateRsa_Pkcs1();

                int cryptoHashAlgorithm = SignatureScheme.GetCryptoHashAlgorithm(signatureScheme);
                FipsShs.Parameters digestParameters = m_crypto.GetDigestParameters(cryptoHashAlgorithm);

                IStreamCalculator<IVerifier> verifier = BcTlsRsaVerifier.CreateVerifier(m_crypto, GetPubKeyRsa(),
                    digestParameters);

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.rsa_pss_pss_sha256:
            case SignatureScheme.rsa_pss_pss_sha384:
            case SignatureScheme.rsa_pss_pss_sha512:
            {
                ValidateRsa_Pss_Pss(SignatureScheme.GetSignatureAlgorithm(signatureScheme));

                IStreamCalculator<IVerifier> verifier = BcTlsRsaPssVerifier.CreateVerifier(m_crypto, GetPubKeyRsa(),
                    signatureScheme);

                return new BcTls13Verifier(verifier);
            }

            case SignatureScheme.rsa_pss_rsae_sha256:
            case SignatureScheme.rsa_pss_rsae_sha384:
            case SignatureScheme.rsa_pss_rsae_sha512:
            {
                ValidateRsa_Pss_Rsae();

                IStreamCalculator<IVerifier> verifier = BcTlsRsaPssVerifier.CreateVerifier(m_crypto, GetPubKeyRsa(),
                    signatureScheme);

                return new BcTls13Verifier(verifier);
            }

            // TODO[RFC 8998]
            //case SignatureScheme.sm2sig_sm3:
            default:
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }
        }

        public virtual X509CertificateStructure X509CertificateStructure
        {
            get { return m_certificate; }
        }

        /// <exception cref="IOException"/>
        public virtual byte[] GetEncoded()
        {
            return m_certificate.GetEncoded(Asn1Encodable.Der);
        }

        /// <exception cref="IOException"/>
        public virtual byte[] GetExtension(DerObjectIdentifier extensionOid)
        {
            X509Extensions extensions = m_certificate.TbsCertificate.Extensions;
            if (extensions != null)
            {
                X509Extension extension = extensions.GetExtension(extensionOid);
                if (extension != null)
                {
                    return Arrays.Clone(extension.Value.GetOctets());
                }
            }
            return null;
        }

        public virtual BigInteger SerialNumber
        {
            get { return m_certificate.SerialNumber.Value; }
        }

        public virtual string SigAlgOid
        {
            get { return m_certificate.SignatureAlgorithm.Algorithm.Id; }
        }

        public virtual Asn1Encodable GetSigAlgParams()
        {
            return m_certificate.SignatureAlgorithm.Parameters;
        }

        /// <exception cref="IOException"/>
        public virtual short GetLegacySignatureAlgorithm()
        {
            IAsymmetricPublicKey publicKey = GetPublicKey();

            if (!SupportsKeyUsage(KeyUsage.DigitalSignature))
                return -1;

            /*
             * RFC 5246 7.4.6. Client Certificate
             */

            /*
             * RSA public key; the certificate MUST allow the key to be used for signing with the
             * signature scheme and hash algorithm that will be employed in the certificate verify
             * message.
             */
            if (publicKey is AsymmetricRsaPublicKey)
                return SignatureAlgorithm.rsa;

            /*
                * DSA public key; the certificate MUST allow the key to be used for signing with the
                * hash algorithm that will be employed in the certificate verify message.
                */
            if (publicKey is AsymmetricDsaPublicKey)
                return SignatureAlgorithm.dsa;

            /*
             * ECDSA-capable public key; the certificate MUST allow the key to be used for signing
             * with the hash algorithm that will be employed in the certificate verify message; the
             * public key MUST use a curve and point format supported by the server.
             */
            if (publicKey is AsymmetricECPublicKey)
            {
                // TODO Check the curve and point format
                return SignatureAlgorithm.ecdsa;
            }

            return -1;
        }

        /// <exception cref="IOException"/>
        public virtual AsymmetricDHPublicKey GetPubKeyDH()
        {
            try
            {
                return (AsymmetricDHPublicKey)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual AsymmetricDsaPublicKey GetPubKeyDss()
        {
            try
            {
                return (AsymmetricDsaPublicKey)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual AsymmetricECPublicKey GetPubKeyEC()
        {
            try
            {
                return (AsymmetricECPublicKey)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual AsymmetricEdDsaPublicKey GetPubKeyEd25519()
        {
            try
            {
                return CheckKeyAlgorithm((AsymmetricEdDsaPublicKey)GetPublicKey(), EdEC.Algorithm.Ed25519);
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual AsymmetricEdDsaPublicKey GetPubKeyEd448()
        {
            try
            {
                return CheckKeyAlgorithm((AsymmetricEdDsaPublicKey)GetPublicKey(), EdEC.Algorithm.Ed448);
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual AsymmetricRsaPublicKey GetPubKeyRsa()
        {
            try
            {
                return (AsymmetricRsaPublicKey)GetPublicKey();
            }
            catch (InvalidCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
            }
        }

        /// <exception cref="IOException"/>
        public virtual bool SupportsSignatureAlgorithm(short signatureAlgorithm)
        {
            return SupportsSignatureAlgorithm(signatureAlgorithm, KeyUsage.DigitalSignature);
        }

        /// <exception cref="IOException"/>
        public virtual bool SupportsSignatureAlgorithmCA(short signatureAlgorithm)
        {
            return SupportsSignatureAlgorithm(signatureAlgorithm, KeyUsage.KeyCertSign);
        }

        /// <exception cref="IOException"/>
        public virtual TlsCertificate CheckUsageInRole(int tlsCertificateRole)
        {
            switch (tlsCertificateRole)
            {
            case TlsCertificateRole.DH:
            {
                ValidateKeyUsage(KeyUsage.KeyAgreement);
                this.m_pubKeyDH = GetPubKeyDH();
                return this;
            }
            case TlsCertificateRole.ECDH:
            {
                ValidateKeyUsage(KeyUsage.KeyAgreement);
                this.m_pubKeyEC = GetPubKeyEC();
                return this;
            }
            }

            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        protected virtual IAsymmetricPublicKey GetPublicKey()
        {
            SubjectPublicKeyInfo keyInfo = m_certificate.SubjectPublicKeyInfo;
            try
            {
                return Core.AsymmetricKeyFactory.CreatePublicKey(keyInfo);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
            }
        }

        protected virtual bool SupportsKeyUsage(int keyUsageBits)
        {
            X509Extensions exts = m_certificate.TbsCertificate.Extensions;
            if (exts != null)
            {
                KeyUsage ku = Core.KeyUsage.FromExtensions(exts);
                if (ku != null)
                {
                    int bits = ku.GetBytes()[0] & 0xff;
                    if ((bits & keyUsageBits) != keyUsageBits)
                        return false;
                }
            }
            return true;
        }

        protected virtual bool SupportsRsa_Pkcs1()
        {
            AlgorithmIdentifier pubKeyAlgID = m_certificate.SubjectPublicKeyInfo.AlgorithmID;
            return RsaUtilities.SupportsPkcs1(pubKeyAlgID);
        }

        protected virtual bool SupportsRsa_Pss_Pss(short signatureAlgorithm)
        {
            AlgorithmIdentifier pubKeyAlgID = m_certificate.SubjectPublicKeyInfo.AlgorithmID;
            return RsaUtilities.SupportsPss_Pss(signatureAlgorithm, pubKeyAlgID);
        }

        protected virtual bool SupportsRsa_Pss_Rsae()
        {
            AlgorithmIdentifier pubKeyAlgID = m_certificate.SubjectPublicKeyInfo.AlgorithmID;
            return RsaUtilities.SupportsPss_Rsae(pubKeyAlgID);
        }

        /// <exception cref="IOException"/>
        protected virtual bool SupportsSignatureAlgorithm(short signatureAlgorithm, int keyUsage)
        {
            if (!SupportsKeyUsage(keyUsage))
                return false;

            IAsymmetricPublicKey publicKey = GetPublicKey();

            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa:
                return SupportsRsa_Pkcs1()
                    && publicKey is AsymmetricRsaPublicKey;

            case SignatureAlgorithm.dsa:
                return publicKey is AsymmetricDsaPublicKey;

            case SignatureAlgorithm.ecdsa:
            case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
            case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
            case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
                return publicKey is AsymmetricECPublicKey;

            case SignatureAlgorithm.ed25519:
                return publicKey is AsymmetricEdDsaPublicKey
                    && HasKeyAlgorithm(publicKey, EdEC.Algorithm.Ed25519);

            case SignatureAlgorithm.ed448:
                return publicKey is AsymmetricEdDsaPublicKey
                    && HasKeyAlgorithm(publicKey, EdEC.Algorithm.Ed448);

            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
                return SupportsRsa_Pss_Rsae()
                    && publicKey is AsymmetricRsaPublicKey;

            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
                return SupportsRsa_Pss_Pss(signatureAlgorithm)
                    && publicKey is AsymmetricRsaPublicKey;

            default:
                return false;
            }
        }

        /// <exception cref="IOException"/>
        public virtual void ValidateKeyUsage(int keyUsageBits)
        {
            if (!SupportsKeyUsage(keyUsageBits))
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateRsa_Pkcs1()
        {
            if (!SupportsRsa_Pkcs1())
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateRsa_Pss_Pss(short signatureAlgorithm)
        {
            if (!SupportsRsa_Pss_Pss(signatureAlgorithm))
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        /// <exception cref="IOException"/>
        protected virtual void ValidateRsa_Pss_Rsae()
        {
            if (!SupportsRsa_Pss_Rsae())
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        private static TKey CheckKeyAlgorithm<TKey>(TKey key, Algorithm algorithm)
            where TKey : IAsymmetricKey
        {
            if (!HasKeyAlgorithm(key, algorithm))
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, "Algorithm mismatch");

            return key;
        }

        private static bool HasKeyAlgorithm(IAsymmetricKey key, Algorithm algorithm)
        {
            return key.Algorithm.Equals(algorithm);
        }
    }
}
