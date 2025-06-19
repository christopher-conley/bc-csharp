using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Operators
{
    public class CmsContentEncryptorBuilder
    {
        private static readonly IDictionary<DerObjectIdentifier,int> KeySizes = new Dictionary<DerObjectIdentifier,int>();

        static CmsContentEncryptorBuilder()
        {
            KeySizes[NistObjectIdentifiers.IdAes128Cbc] = 128;
            KeySizes[NistObjectIdentifiers.IdAes192Cbc] = 192;
            KeySizes[NistObjectIdentifiers.IdAes256Cbc] = 256;


            KeySizes[NttObjectIdentifiers.IdCamellia128Cbc] = 128;
            KeySizes[NttObjectIdentifiers.IdCamellia192Cbc] = 192;
            KeySizes[NttObjectIdentifiers.IdCamellia256Cbc] = 256;
        }

        private static int GetKeySize(DerObjectIdentifier oid)
        {
           
            if (KeySizes.ContainsKey(oid))
            {
                return KeySizes[oid];
            }

            return -1;
        }

        private readonly DerObjectIdentifier encryptionOID;
        private readonly int keySize;

        public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID) : this(encryptionOID,  (int)Utils.keySizesInBytes[encryptionOID])
        {
        }

        public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID, int keySize)
        {
            this.encryptionOID = encryptionOID;
            this.keySize = keySize;
        }

        public ICipherBuilderWithKey<AlgorithmIdentifier> Build() 
        {            
            return new PkixContentEncryptor(encryptionOID,CryptoServicesRegistrar.GetSecureRandom());            
        }
    }
}