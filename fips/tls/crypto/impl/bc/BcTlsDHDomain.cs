using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>BC light-weight support class for Diffie-Hellman key pair generation and key agreement over a
    /// specified Diffie-Hellman configuration.</summary>
    public class BcTlsDHDomain
        : TlsDHDomain
    {
        private static byte[] EncodeValue(DHDomainParameters dh, bool padded, BigInteger x)
        {
            return padded
                ? BigIntegers.AsUnsignedByteArray(GetValueLength(dh), x)
                : BigIntegers.AsUnsignedByteArray(x);
        }

        private static int GetValueLength(DHDomainParameters dh)
        {
            return (dh.P.BitLength + 7) / 8;
        }

        public static BcTlsSecret CalculateDHAgreement(BcTlsCrypto crypto, AsymmetricDHPrivateKey privateKey,
            AsymmetricDHPublicKey publicKey, bool padded)
        {
            IAgreementCalculatorService service = CryptoServicesRegistrar.CreateService(privateKey);
            IAgreementCalculator<FipsDH.AgreementParameters> calculator = service.CreateAgreementCalculator(FipsDH.DH);
            byte[] secret = calculator.Calculate(publicKey);

            if (!padded)
            {
                int length = secret.Length, pos = 0;
                while(pos < length && secret[pos] == 0)
                {
                    ++pos;
                }
                if (pos > 0)
                {
                    byte[] tmp = Arrays.CopyOfRange(secret, pos, length);
                    Arrays.Clear(secret);
                    secret = tmp;
                }
            }

            return crypto.AdoptLocalSecret(secret);
        }

        public static DHDomainParameters GetDomainParameters(TlsDHConfig dhConfig)
        {
            DHGroup dhGroup = TlsDHUtilities.GetDHGroup(dhConfig);
            if (dhGroup == null)
                throw new ArgumentException("No DH configuration provided");

            return new DHDomainParameters(dhGroup.P, dhGroup.Q, dhGroup.G, dhGroup.L);
        }

        protected readonly BcTlsCrypto m_crypto;
        protected readonly TlsDHConfig m_config;
        protected readonly DHDomainParameters m_domainParameters;

        public BcTlsDHDomain(BcTlsCrypto crypto, TlsDHConfig dhConfig)
        {
            this.m_crypto = crypto;
            this.m_config = dhConfig;
            this.m_domainParameters = GetDomainParameters(dhConfig);
        }

        public virtual BcTlsSecret CalculateDHAgreement(AsymmetricDHPrivateKey privateKey,
            AsymmetricDHPublicKey publicKey)
        {
            return CalculateDHAgreement(m_crypto, privateKey, publicKey, m_config.IsPadded);
        }

        public virtual TlsAgreement CreateDH()
        {
            return new BcTlsDH(this);
        }

        /// <exception cref="IOException"/>
        public virtual BigInteger DecodeParameter(byte[] encoding)
        {
            if (m_config.IsPadded && GetValueLength(m_domainParameters) != encoding.Length)
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            return new BigInteger(1, encoding);
        }

        /// <exception cref="IOException"/>
        public virtual AsymmetricDHPublicKey DecodePublicKey(byte[] encoding)
        {
            /*
             * RFC 7919 3. [..] the client MUST verify that dh_Ys is in the range 1 < dh_Ys < dh_p - 1.
             * If dh_Ys is not in this range, the client MUST terminate the connection with a fatal
             * handshake_failure(40) alert.
             */
            try
            {
                BigInteger y = DecodeParameter(encoding);

                return new AsymmetricDHPublicKey(FipsDH.Alg, m_domainParameters, y);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure, e);
            }
        }

        public virtual byte[] EncodeParameter(BigInteger x)
        {
            return EncodeValue(m_domainParameters, m_config.IsPadded, x);
        }

        public virtual byte[] EncodePublicKey(AsymmetricDHPublicKey publicKey)
        {
            return EncodeValue(m_domainParameters, true, publicKey.Y);
        }

        public virtual AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey> GenerateKeyPair()
        {
            FipsDH.KeyPairGenerator kpGen = CryptoServicesRegistrar.CreateGenerator(
                new FipsDH.KeyGenerationParameters(m_domainParameters),
                m_crypto.SecureRandom);

            return kpGen.GenerateKeyPair();
        }
    }
}
