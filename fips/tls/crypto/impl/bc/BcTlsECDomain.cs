using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /**
     * EC domain class for generating key pairs and performing key agreement.
     */
    public class BcTlsECDomain
        : TlsECDomain
    {
        public static BcTlsSecret CalculateECDHAgreement(BcTlsCrypto crypto, AsymmetricECPrivateKey privateKey,
            AsymmetricECPublicKey publicKey)
        {
            IAgreementCalculatorService service = CryptoServicesRegistrar.CreateService(privateKey);
            // TODO[tls-fips] Review the use of 'Cdh' here
            IAgreementCalculator<FipsEC.AgreementParameters> calculator = service.CreateAgreementCalculator(FipsEC.Cdh);

            /*
             * RFC 4492 5.10. Note that this octet string (Z in IEEE 1363 terminology) as output by
             * FE2OSP, the Field Element to Octet String Conversion Primitive, has constant length for
             * any given field; leading zeros found in this octet string MUST NOT be truncated.
             */

            byte[] secret = calculator.Calculate(publicKey);
            return crypto.AdoptLocalSecret(secret);
        }

        public static ECDomainParameters GetDomainParameters(TlsECConfig ecConfig)
        {
            return GetDomainParameters(ecConfig.NamedGroup);
        }

        public static ECDomainParameters GetDomainParameters(int namedGroup)
        {
            if (!NamedGroup.RefersToASpecificCurve(namedGroup))
                return null;

            string curveName = NamedGroup.GetCurveName(namedGroup);
            TlsCurve curve = new TlsCurve(curveName);
            return ECDomainParametersIndex.LookupDomainParameters(curve);
        }

        protected readonly BcTlsCrypto m_crypto;
        protected readonly TlsECConfig m_config;
        protected readonly ECDomainParameters m_domainParameters;

        public BcTlsECDomain(BcTlsCrypto crypto, TlsECConfig ecConfig)
        {
            this.m_crypto = crypto;
            this.m_config = ecConfig;
            this.m_domainParameters = GetDomainParameters(ecConfig);
        }

        public virtual BcTlsSecret CalculateECDHAgreement(AsymmetricECPrivateKey privateKey,
            AsymmetricECPublicKey publicKey)
        {
            return CalculateECDHAgreement(m_crypto, privateKey, publicKey);
        }

        public virtual TlsAgreement CreateECDH()
        {
            return new BcTlsECDH(this);
        }

        public virtual ECPoint DecodePoint(byte[] encoding)
        {
            return m_domainParameters.Curve.DecodePoint(encoding);
        }

        /// <exception cref="IOException"/>
        public virtual AsymmetricECPublicKey DecodePublicKey(byte[] encoding)
        {
            try
            {
                ECPoint point = DecodePoint(encoding);

                return new AsymmetricECPublicKey(FipsEC.Alg, m_domainParameters, point);
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
            }
        }

        public virtual byte[] EncodePoint(ECPoint point)
        {
            return point.GetEncoded(false);
        }

        public virtual byte[] EncodePublicKey(AsymmetricECPublicKey publicKey)
        {
            return EncodePoint(publicKey.W);
        }

        public virtual AsymmetricKeyPair<AsymmetricECPublicKey, AsymmetricECPrivateKey> GenerateKeyPair()
        {
            FipsEC.KeyPairGenerator kpGen = CryptoServicesRegistrar.CreateGenerator(
                new FipsEC.KeyGenerationParameters(m_domainParameters),
                m_crypto.SecureRandom);

            return kpGen.GenerateKeyPair();
        }

        // TODO[tls-fips] Review the need to wrap the curve name for lookup
        private class TlsCurve
            : IECDomainParametersID
        {
            private readonly string m_curveName;

            internal TlsCurve(string curveName)
            {
                this.m_curveName = curveName;
            }

            public string CurveName
            {
                get { return m_curveName; }
            }
        }
    }
}
