using System;
using System.Collections;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /**
     * Class for providing cryptographic services for TLS based on implementations in the BC light-weight API.
     * <p>
     *     This class provides default implementations for everything. If you need to customise it, extend the class
     *     and override the appropriate methods.
     * </p>
     */
    public class BcTlsCrypto
        : AbstractTlsCrypto
    {
        private readonly IEntropySourceProvider m_entropySource;
        private readonly SecureRandom m_random;

        public BcTlsCrypto(SecureRandom entropySource)
        {
            this.m_entropySource = new BasicEntropySourceProvider(entropySource, true);
            byte[] nonce = entropySource.GenerateSeed(32);
            this.m_random = CryptoServicesRegistrar.CreateService(FipsDrbg.Sha512)
                .FromEntropySource(m_entropySource).Build(nonce, false);
        }

        internal virtual BcTlsSecret AdoptLocalSecret(byte[] data)
        {
            return new BcTlsSecret(this, data);
        }

        public override SecureRandom SecureRandom
        {
            get { return m_random; }
        }

        public override TlsCertificate CreateCertificate(byte[] encoding)
        {
            return new BcTlsCertificate(this, encoding);
        }

        public override TlsCipher CreateCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm,
            int macAlgorithm)
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm.AES_128_CBC:
            case EncryptionAlgorithm.CAMELLIA_128_CBC:
            case EncryptionAlgorithm.SEED_CBC:
                return CreateBlockCipher(cryptoParams, encryptionAlgorithm, 16, macAlgorithm);

            case EncryptionAlgorithm.cls_3DES_EDE_CBC:
                return CreateBlockCipher(cryptoParams, encryptionAlgorithm, 24, macAlgorithm);

            case EncryptionAlgorithm.AES_256_CBC:
            case EncryptionAlgorithm.CAMELLIA_256_CBC:
                return CreateBlockCipher(cryptoParams, encryptionAlgorithm, 32, macAlgorithm);

            case EncryptionAlgorithm.AES_128_CCM:
                // NOTE: Ignores macAlgorithm
                return CreateAeadCipher(cryptoParams, encryptionAlgorithm, 16, 16, TlsAeadCipher.AEAD_CCM);
            case EncryptionAlgorithm.AES_128_CCM_8:
                // NOTE: Ignores macAlgorithm
                return CreateAeadCipher(cryptoParams, encryptionAlgorithm, 16, 8, TlsAeadCipher.AEAD_CCM);
            case EncryptionAlgorithm.AES_128_GCM:
            case EncryptionAlgorithm.CAMELLIA_128_GCM:
                // NOTE: Ignores macAlgorithm
                return CreateAeadCipher(cryptoParams, encryptionAlgorithm, 16, 16, TlsAeadCipher.AEAD_GCM);
            case EncryptionAlgorithm.AES_256_CCM:
                // NOTE: Ignores macAlgorithm
                return CreateAeadCipher(cryptoParams, encryptionAlgorithm, 32, 16, TlsAeadCipher.AEAD_CCM);
            case EncryptionAlgorithm.AES_256_CCM_8:
                // NOTE: Ignores macAlgorithm
                return CreateAeadCipher(cryptoParams, encryptionAlgorithm, 32, 8, TlsAeadCipher.AEAD_CCM);
            case EncryptionAlgorithm.AES_256_GCM:
            case EncryptionAlgorithm.CAMELLIA_256_GCM:
                // NOTE: Ignores macAlgorithm
                return CreateAeadCipher(cryptoParams, encryptionAlgorithm, 32, 16, TlsAeadCipher.AEAD_GCM);
            //case EncryptionAlgorithm.CHACHA20_POLY1305:
            //    // NOTE: Ignores macAlgorithm
            //    return CreateChaCha20Poly1305(cryptoParams);
            case EncryptionAlgorithm.NULL:
                return CreateNullCipher(cryptoParams, macAlgorithm);

            case EncryptionAlgorithm.ARIA_128_CBC:
            case EncryptionAlgorithm.ARIA_128_GCM:
            case EncryptionAlgorithm.ARIA_256_CBC:
            case EncryptionAlgorithm.ARIA_256_GCM:
            case EncryptionAlgorithm.CHACHA20_POLY1305:
            case EncryptionAlgorithm.DES40_CBC:
            case EncryptionAlgorithm.DES_CBC:
            case EncryptionAlgorithm.IDEA_CBC:
            case EncryptionAlgorithm.RC2_CBC_40:
            case EncryptionAlgorithm.RC4_128:
            case EncryptionAlgorithm.RC4_40:
            case EncryptionAlgorithm.SM4_CBC:
            case EncryptionAlgorithm.SM4_CCM:
            case EncryptionAlgorithm.SM4_GCM:
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public override TlsDHDomain CreateDHDomain(TlsDHConfig dhConfig)
        {
            return new BcTlsDHDomain(this, dhConfig);
        }

        public override TlsECDomain CreateECDomain(TlsECConfig ecConfig)
        {
            switch (ecConfig.NamedGroup)
            {
            //case NamedGroup.x25519:
            //    return new BcX25519Domain(this);
            //case NamedGroup.x448:
            //    return new BcX448Domain(this);
            case NamedGroup.x25519:
            case NamedGroup.x448:
                throw new NotSupportedException("unsupported NamedGroup: " + ecConfig.NamedGroup);

            default:
                return new BcTlsECDomain(this, ecConfig);
            }
        }

        public override TlsNonceGenerator CreateNonceGenerator(byte[] additionalSeedMaterial)
        {
            byte[] nonce = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
            SecureRandom random = CryptoServicesRegistrar.CreateService(FipsDrbg.Sha256)
                .FromEntropySource(m_entropySource).SetPersonalizationString(additionalSeedMaterial).Build(nonce, false);

            return new BcTlsNonceGenerator(random);
        }

        public override bool HasAnyStreamVerifiers(IList signatureAndHashAlgorithms)
        {
            foreach (SignatureAndHashAlgorithm algorithm in signatureAndHashAlgorithms)
            {
                // TODO[tls-fips] This should change once core is updated
                switch (algorithm.Signature)
                {
                case SignatureAlgorithm.rsa:
                case SignatureAlgorithm.dsa:
                    return true;
                }

                switch (SignatureScheme.From(algorithm))
                {
                case SignatureScheme.ed25519:
                case SignatureScheme.ed448:
                    return true;

                // TODO[tls-fips] This should change once core is updated
                case SignatureScheme.rsa_pss_rsae_sha256:
                case SignatureScheme.rsa_pss_rsae_sha384:
                case SignatureScheme.rsa_pss_rsae_sha512:
                case SignatureScheme.rsa_pss_pss_sha256:
                case SignatureScheme.rsa_pss_pss_sha384:
                case SignatureScheme.rsa_pss_pss_sha512:
                    return true;
                }
            }
            return false;
        }

        public override bool HasAnyStreamVerifiersLegacy(short[] clientCertificateTypes)
        {
            // TODO[tls-fips] This should change once core is updated
            foreach (short clientCertificateType in clientCertificateTypes)
            {
                switch (clientCertificateType)
                {
                case ClientCertificateType.rsa_sign:
                case ClientCertificateType.dss_sign:
                    return true;
                }
            }
            return false;
        }

        public override bool HasCryptoHashAlgorithm(int cryptoHashAlgorithm)
        {
            switch (cryptoHashAlgorithm)
            {
            case CryptoHashAlgorithm.md5:
            case CryptoHashAlgorithm.sha1:
            case CryptoHashAlgorithm.sha224:
            case CryptoHashAlgorithm.sha256:
            case CryptoHashAlgorithm.sha384:
            case CryptoHashAlgorithm.sha512:
                return true;

            case CryptoHashAlgorithm.sm3:
            default:
                return false;
            }
        }

        public override bool HasCryptoSignatureAlgorithm(int cryptoSignatureAlgorithm)
        {
            switch (cryptoSignatureAlgorithm)
            {
            case CryptoSignatureAlgorithm.rsa:
            case CryptoSignatureAlgorithm.dsa:
            case CryptoSignatureAlgorithm.ecdsa:
            case CryptoSignatureAlgorithm.rsa_pss_rsae_sha256:
            case CryptoSignatureAlgorithm.rsa_pss_rsae_sha384:
            case CryptoSignatureAlgorithm.rsa_pss_rsae_sha512:
            case CryptoSignatureAlgorithm.ed25519:
            case CryptoSignatureAlgorithm.ed448:
            case CryptoSignatureAlgorithm.rsa_pss_pss_sha256:
            case CryptoSignatureAlgorithm.rsa_pss_pss_sha384:
            case CryptoSignatureAlgorithm.rsa_pss_pss_sha512:
                return true;

            // TODO[draft-smyshlyaev-tls12-gost-suites-10]
            case CryptoSignatureAlgorithm.gostr34102012_256:
            case CryptoSignatureAlgorithm.gostr34102012_512:

            // TODO[RFC 8998]
            case CryptoSignatureAlgorithm.sm2:

            default:
                return false;
            }
        }

        public override bool HasDHAgreement()
        {
            return true;
        }

        public override bool HasECDHAgreement()
        {
            return true;
        }

        public override bool HasEncryptionAlgorithm(int encryptionAlgorithm)
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm.AES_128_CBC:
            case EncryptionAlgorithm.AES_128_CCM:
            case EncryptionAlgorithm.AES_128_CCM_8:
            case EncryptionAlgorithm.AES_128_GCM:
            case EncryptionAlgorithm.AES_256_CBC:
            case EncryptionAlgorithm.AES_256_CCM:
            case EncryptionAlgorithm.AES_256_CCM_8:
            case EncryptionAlgorithm.AES_256_GCM:
            case EncryptionAlgorithm.CAMELLIA_128_CBC:
            case EncryptionAlgorithm.CAMELLIA_128_GCM:
            case EncryptionAlgorithm.CAMELLIA_256_CBC:
            case EncryptionAlgorithm.CAMELLIA_256_GCM:
            case EncryptionAlgorithm.cls_3DES_EDE_CBC:
            case EncryptionAlgorithm.NULL:
            case EncryptionAlgorithm.SEED_CBC:
                return true;

            case EncryptionAlgorithm.ARIA_128_CBC:
            case EncryptionAlgorithm.ARIA_128_GCM:
            case EncryptionAlgorithm.ARIA_256_CBC:
            case EncryptionAlgorithm.ARIA_256_GCM:
            case EncryptionAlgorithm.CHACHA20_POLY1305:
            case EncryptionAlgorithm.DES_CBC:
            case EncryptionAlgorithm.DES40_CBC:
            case EncryptionAlgorithm.IDEA_CBC:
            case EncryptionAlgorithm.RC2_CBC_40:
            case EncryptionAlgorithm.RC4_128:
            case EncryptionAlgorithm.RC4_40:
            case EncryptionAlgorithm.SM4_CBC:
            case EncryptionAlgorithm.SM4_CCM:
            case EncryptionAlgorithm.SM4_GCM:
            default:
                return false;
            }
        }

        public override bool HasHkdfAlgorithm(int cryptoHashAlgorithm)
        {
            switch (cryptoHashAlgorithm)
            {
            case CryptoHashAlgorithm.sha256:
            case CryptoHashAlgorithm.sha384:
            case CryptoHashAlgorithm.sha512:
                return true;

            default:
                return false;
            }
        }

        public override bool HasMacAlgorithm(int macAlgorithm)
        {
            switch (macAlgorithm)
            {
            case MacAlgorithm.hmac_sha1:
            case MacAlgorithm.hmac_sha256:
            case MacAlgorithm.hmac_sha384:
            case MacAlgorithm.hmac_sha512:
                return true;

            case MacAlgorithm.hmac_md5:
            default:
                return false;
            }
        }

        public override bool HasNamedGroup(int namedGroup)
        {
            switch (namedGroup)
            {
            case NamedGroup.x25519:
            case NamedGroup.x448:
                return false;

            // TODO[tls-fips] Further restrictions?
            default:
                return NamedGroup.RefersToASpecificGroup(namedGroup);
            }
        }

        public override bool HasRsaEncryption()
        {
            return true;
        }

        public override bool HasSignatureAlgorithm(short signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
            case SignatureAlgorithm.rsa:
            case SignatureAlgorithm.dsa:
            case SignatureAlgorithm.ecdsa:
            case SignatureAlgorithm.ed25519:
            case SignatureAlgorithm.ed448:
            case SignatureAlgorithm.rsa_pss_rsae_sha256:
            case SignatureAlgorithm.rsa_pss_rsae_sha384:
            case SignatureAlgorithm.rsa_pss_rsae_sha512:
            case SignatureAlgorithm.rsa_pss_pss_sha256:
            case SignatureAlgorithm.rsa_pss_pss_sha384:
            case SignatureAlgorithm.rsa_pss_pss_sha512:
            case SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256:
            case SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384:
            case SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512:
                return true;

            // TODO[draft-smyshlyaev-tls12-gost-suites-10]
            case SignatureAlgorithm.gostr34102012_256:
            case SignatureAlgorithm.gostr34102012_512:
            // TODO[RFC 8998]
            //case SignatureAlgorithm.sm2:
            default:
                return false;
            }
        }

        public override bool HasSignatureAndHashAlgorithm(SignatureAndHashAlgorithm sigAndHashAlgorithm)
        {
            short signature = sigAndHashAlgorithm.Signature;

            switch (sigAndHashAlgorithm.Hash)
            {
            case HashAlgorithm.md5:
                return false;
            default:
                return HasSignatureAlgorithm(signature);
            }
        }

        public override bool HasSignatureScheme(int signatureScheme)
        {
            switch (signatureScheme)
            {
            case SignatureScheme.sm2sig_sm3:
                return false;
            default:
            {
                short signature = SignatureScheme.GetSignatureAlgorithm(signatureScheme);

                switch(SignatureScheme.GetCryptoHashAlgorithm(signatureScheme))
                {
                case CryptoHashAlgorithm.md5:
                    return false;
                default:
                    return HasSignatureAlgorithm(signature);
                }
            }
            }
        }

        public override TlsSecret CreateSecret(byte[] data)
        {
            try
            {
                return AdoptLocalSecret(Arrays.Clone(data));
            }
            finally
            {
                // TODO[tls-ops] Add this after checking all callers
                //if (data != null)
                //{
                //    Array.Clear(data, 0, data.Length);
                //}
            }
        }

        public override TlsSecret GenerateRsaPreMasterSecret(ProtocolVersion version)
        {
            byte[] data = new byte[48];
            SecureRandom.NextBytes(data);
            TlsUtilities.WriteVersion(version, data, 0);
            return AdoptLocalSecret(data);
        }

        public virtual IStreamCalculator<IBlockResult> CreateDigest(int cryptoHashAlgorithm)
        {
            return CreateDigestService(cryptoHashAlgorithm).CreateCalculator();
        }

        public virtual IDigestFactory<FipsShs.Parameters> CreateDigestService(int cryptoHashAlgorithm)
        {
            return CryptoServicesRegistrar.CreateService(GetDigestParameters(cryptoHashAlgorithm));
        }

        public override TlsHash CreateHash(int cryptoHashAlgorithm)
        {
            switch (cryptoHashAlgorithm)
            {
            case CryptoHashAlgorithm.md5:
                return new Md5Hash();

            case CryptoHashAlgorithm.sha1:
            case CryptoHashAlgorithm.sha224:
            case CryptoHashAlgorithm.sha256:
            case CryptoHashAlgorithm.sha384:
            case CryptoHashAlgorithm.sha512:
                return new BcTlsHash(this, cryptoHashAlgorithm);

            case CryptoHashAlgorithm.sm3:
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        public virtual FipsShs.Parameters GetDigestParameters(int cryptoHashAlgorithm)
        {
            switch (cryptoHashAlgorithm)
            {
            case CryptoHashAlgorithm.sha1:
                return FipsShs.Sha1;
            case CryptoHashAlgorithm.sha224:
                return FipsShs.Sha224;
            case CryptoHashAlgorithm.sha256:
                return FipsShs.Sha256;
            case CryptoHashAlgorithm.sha384:
                return FipsShs.Sha384;
            case CryptoHashAlgorithm.sha512:
                return FipsShs.Sha512;
            case CryptoHashAlgorithm.md5:
            case CryptoHashAlgorithm.sm3:
                throw new NotSupportedException("unsupported CryptoHashAlgorithm: " + cryptoHashAlgorithm);
            default:
                throw new ArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
            }
        }

        public virtual FipsShs.AuthenticationParameters GetHmacParameters(int cryptoHashAlgorithm)
        {
            switch (cryptoHashAlgorithm)
            {
            case CryptoHashAlgorithm.sha1:
                return FipsShs.Sha1HMac;
            case CryptoHashAlgorithm.sha224:
                return FipsShs.Sha224HMac;
            case CryptoHashAlgorithm.sha256:
                return FipsShs.Sha256HMac;
            case CryptoHashAlgorithm.sha384:
                return FipsShs.Sha384HMac;
            case CryptoHashAlgorithm.sha512:
                return FipsShs.Sha512HMac;
            case CryptoHashAlgorithm.md5:
            case CryptoHashAlgorithm.sm3:
                throw new NotSupportedException("unsupported HMAC CryptoHashAlgorithm: " + cryptoHashAlgorithm);
            default:
                throw new ArgumentException("invalid CryptoHashAlgorithm: " + cryptoHashAlgorithm);
            }
        }

        public override TlsHmac CreateHmac(int macAlgorithm)
        {
            switch (macAlgorithm)
            {
            case MacAlgorithm.hmac_sha1:
            case MacAlgorithm.hmac_sha256:
            case MacAlgorithm.hmac_sha384:
            case MacAlgorithm.hmac_sha512:
                return CreateHmacForHash(TlsCryptoUtilities.GetHashForHmac(macAlgorithm));

            case MacAlgorithm.hmac_md5:
                throw new NotSupportedException("unsupported MacAlgorithm: " + macAlgorithm);

            default:
                throw new ArgumentException("invalid MacAlgorithm: " + macAlgorithm);
            }
        }

        public override TlsHmac CreateHmacForHash(int cryptoHashAlgorithm)
        {
            return new BcTlsHmac(this, cryptoHashAlgorithm);
        }

        public override TlsSecret HkdfInit(int cryptoHashAlgorithm)
        {
            return AdoptLocalSecret(new byte[TlsCryptoUtilities.GetHashOutputSize(cryptoHashAlgorithm)]);
        }

        protected virtual TlsAeadCipher CreateAeadCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm,
            int cipherKeySize, int macSize, int aeadType)
        {
            TlsAeadCipherImpl encrypt = CreateAeadCipherImpl(encryptionAlgorithm, true);
            TlsAeadCipherImpl decrypt = CreateAeadCipherImpl(encryptionAlgorithm, false);

            return new TlsAeadCipher(cryptoParams, encrypt, decrypt, cipherKeySize, macSize, aeadType);
        }

        protected virtual TlsAeadCipherImpl CreateAeadCipherImpl(int encryptionAlgorithm, bool isEncrypting)
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm.AES_128_CCM:
            case EncryptionAlgorithm.AES_128_CCM_8:
                return new BcTlsAeadCipherImpl<FipsAes.AuthenticationParametersWithIV, FipsAlgorithm>(
                    FipsAes.Ccm, isEncrypting, keyBytes => new FipsAes.Key(FipsAes.Alg128, keyBytes));
            case EncryptionAlgorithm.AES_128_GCM:
                return new BcTlsAeadCipherImpl<FipsAes.AuthenticationParametersWithIV, FipsAlgorithm>(
                    FipsAes.Gcm, isEncrypting, keyBytes => new FipsAes.Key(FipsAes.Alg128, keyBytes));
            case EncryptionAlgorithm.AES_256_CCM:
            case EncryptionAlgorithm.AES_256_CCM_8:
                return new BcTlsAeadCipherImpl<FipsAes.AuthenticationParametersWithIV, FipsAlgorithm>(
                    FipsAes.Ccm, isEncrypting, keyBytes => new FipsAes.Key(FipsAes.Alg256, keyBytes));
            case EncryptionAlgorithm.AES_256_GCM:
                return new BcTlsAeadCipherImpl<FipsAes.AuthenticationParametersWithIV, FipsAlgorithm>(
                    FipsAes.Gcm, isEncrypting, keyBytes => new FipsAes.Key(FipsAes.Alg256, keyBytes));
            case EncryptionAlgorithm.CAMELLIA_128_GCM:
                return new BcTlsAeadCipherImpl<Camellia.AuthenticationParametersWithIV, GeneralAlgorithm>(
                    Camellia.Gcm, isEncrypting, keyBytes => new Camellia.Key(Camellia.Alg128, keyBytes));
            case EncryptionAlgorithm.CAMELLIA_256_GCM:
                return new BcTlsAeadCipherImpl<Camellia.AuthenticationParametersWithIV, GeneralAlgorithm>(
                    Camellia.Gcm, isEncrypting, keyBytes => new Camellia.Key(Camellia.Alg256, keyBytes));
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        protected virtual TlsCipher CreateBlockCipher(TlsCryptoParameters cryptoParams, int encryptionAlgorithm,
            int cipherKeySize, int macAlgorithm)
        {
            TlsBlockCipherImpl encrypt = CreateBlockCipherImpl(encryptionAlgorithm, true);
            TlsBlockCipherImpl decrypt = CreateBlockCipherImpl(encryptionAlgorithm, false);

            TlsHmac clientMac = CreateHmac(macAlgorithm);
            TlsHmac serverMac = CreateHmac(macAlgorithm);

            return new TlsBlockCipher(cryptoParams, encrypt, decrypt, clientMac, serverMac, cipherKeySize);
        }

        protected virtual TlsBlockCipherImpl CreateBlockCipherImpl(int encryptionAlgorithm, bool isEncrypting)
        {
            switch (encryptionAlgorithm)
            {
            case EncryptionAlgorithm.cls_3DES_EDE_CBC:
                return new BcTlsBlockCipherImpl<FipsTripleDes.ParametersWithIV, FipsAlgorithm>(8,
                    FipsTripleDes.Cbc, isEncrypting, keyBytes => new FipsTripleDes.Key(FipsTripleDes.Alg168, keyBytes));
            case EncryptionAlgorithm.AES_128_CBC:
                return new BcTlsBlockCipherImpl<FipsAes.ParametersWithIV, FipsAlgorithm>(16,
                    FipsAes.Cbc, isEncrypting, keyBytes => new FipsAes.Key(FipsAes.Alg128, keyBytes));
            case EncryptionAlgorithm.AES_256_CBC:
                return new BcTlsBlockCipherImpl<FipsAes.ParametersWithIV, FipsAlgorithm>(16,
                    FipsAes.Cbc, isEncrypting, keyBytes => new FipsAes.Key(FipsAes.Alg256, keyBytes));
            case EncryptionAlgorithm.CAMELLIA_128_CBC:
                return new BcTlsBlockCipherImpl<Camellia.ParametersWithIV, GeneralAlgorithm>(16,
                    Camellia.Cbc, isEncrypting, keyBytes => new Camellia.Key(Camellia.Alg128, keyBytes));
            case EncryptionAlgorithm.CAMELLIA_256_CBC:
                return new BcTlsBlockCipherImpl<Camellia.ParametersWithIV, GeneralAlgorithm>(16,
                    Camellia.Cbc, isEncrypting, keyBytes => new Camellia.Key(Camellia.Alg256, keyBytes));
            case EncryptionAlgorithm.SEED_CBC:
                return new BcTlsBlockCipherImpl<Seed.ParametersWithIV, GeneralAlgorithm>(16,
                    Seed.Cbc, isEncrypting, keyBytes => new Seed.Key(keyBytes));
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        //protected virtual TlsCipher CreateChaCha20Poly1305(TlsCryptoParameters cryptoParams)
        //{
        //    BcChaCha20Poly1305 encrypt = new BcChaCha20Poly1305(true);
        //    BcChaCha20Poly1305 decrypt = new BcChaCha20Poly1305(false);

        //    return new TlsAeadCipher(cryptoParams, encrypt, decrypt, 32, 16, TlsAeadCipher.AEAD_CHACHA20_POLY1305);
        //}

        protected virtual TlsNullCipher CreateNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)
        {
            return new TlsNullCipher(cryptoParams, CreateHmac(macAlgorithm), CreateHmac(macAlgorithm));
        }

        /// <exception cref="IOException"/>
        internal static byte[] CollectResult(IStreamCalculator<IBlockResult> calculator)
        {
            try
            {
                calculator.Stream.Close();

                return calculator.GetResult().Collect();
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }

        /// <exception cref="IOException"/>
        internal static bool IsVerifiedResult(IStreamCalculator<IVerifier> calculator, byte[] signature)
        {
            try
            {
                calculator.Stream.Close();

                return calculator.GetResult().IsVerified(signature);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }
    }
}
