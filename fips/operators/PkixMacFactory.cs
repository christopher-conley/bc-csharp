using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Operators
{
    public class PkixMacFactory : IMacFactory<AlgorithmIdentifier>
    {
        private readonly AlgorithmIdentifier algorithmID;
        private readonly IMacFactory<FipsShs.AuthenticationParameters> macFactory;

        public PkixMacFactory(AlgorithmIdentifier algorithmID, byte[] keyBytes)
        {
            this.algorithmID = algorithmID;
            FipsShs.AuthenticationParameters param =
                (FipsShs.AuthenticationParameters) Utils.macParams[((PbmParameter)(algorithmID.Parameters)).Mac.Algorithm];
            var key = new FipsShs.Key(param,keyBytes);

            macFactory = CryptoServicesRegistrar.CreateService(key).CreateMacFactory(param);
        }


        public PkixMacFactory(FipsShs.Key key,AlgorithmIdentifier algorithmID)
        {
            this.algorithmID = algorithmID;               
             macFactory = CryptoServicesRegistrar.CreateService(key).CreateMacFactory((FipsShs.AuthenticationParameters)Utils.digestTable[algorithmID.Algorithm]);          
        }

        public AlgorithmIdentifier AlgorithmDetails
        {
            get
            {
                return algorithmID;
            }
        }

        public int MacLength {
            get { return macFactory.MacLength; }            
        }


        public IStreamCalculator<IBlockResult> CreateCalculator()
        {
            return macFactory.CreateCalculator();
        }
    }
}
