using System;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crmf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Operators
{
    public class DefaultPKMacPrimitivesProvider:IPKMacPrimitivesProvider
    {
        public IDigestFactory<FipsShs.Parameters> CreateDigest(AlgorithmIdentifier digestAlg)
        {          
            return CryptoServicesRegistrar.CreateService((FipsShs.Parameters)Utils.digestTable[digestAlg.Algorithm]);
        }

        public IMacFactory<FipsShs.AuthenticationParameters> CreateMac(AlgorithmIdentifier macAlg)
        {
            //return CryptoServicesRegistrar.CreateService(
            //    (FipsShs.AuthenticationParameters) Utils.macParams[macAlg.Algorithm]);

            //CryptoServicesRegistrar.CreateService(
            //    (FipsShs.AuthenticationParameters) Utils.digestTable[macAlg.Algorithm]);

            return null;
        }
    }
}