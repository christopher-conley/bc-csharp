using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Crmf
{
    public interface IPKMacPrimitivesProvider
    {
        IDigestFactory<FipsShs.Parameters> CreateDigest(AlgorithmIdentifier digestAlg);

        IMacFactory<FipsShs.AuthenticationParameters> CreateMac(AlgorithmIdentifier macAlg);
    }
}