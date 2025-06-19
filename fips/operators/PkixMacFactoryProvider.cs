using System;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Operators
{
    public class PkixMacFactoryProvider : IMacFactoryProvider<AlgorithmIdentifier>
    {
        public PkixMacFactoryProvider()
        {
        }

      

        public IMacFactory<AlgorithmIdentifier> CreateMacFactory(AlgorithmIdentifier algorithmDetails)
        {
            //new PkixMacFactory(algorithmDetails.Algorithm)
            return null;
        }
    }
}
