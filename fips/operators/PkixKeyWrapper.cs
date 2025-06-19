using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Operators
{
    public class PkixKeyWrapper:IKeyWrapper<AlgorithmIdentifier>
    {


        private static readonly IDictionary<string,Func<AlgorithmIdentifier>> nameToAlgo = new Dictionary<string, Func<AlgorithmIdentifier>>();


        static PkixKeyWrapper()
        {
            nameToAlgo["RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING"] = delegate()
            {
                return new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            };

            nameToAlgo["RSA/NONE/OAEPWITHSHA224ANDMGF1PADDING"] = delegate()
            {
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
            };

            nameToAlgo["RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING"] = delegate()
            {
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
            };

            nameToAlgo["RSA/NONE/OAEPWITHSHA384ANDMGF1PADDING"] = delegate()
            {
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
            };

            nameToAlgo["RSA/NONE/OAEPWITHSHA512ANDMGF1PADDING"] = delegate()
            {
                return new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
            };
        }

        private readonly IKeyWrapper<FipsRsa.OaepWrapParameters> wrapper;
        private readonly AlgorithmIdentifier algorithmIdentifier;

        public PkixKeyWrapper(String name, IAsymmetricPublicKey key)
        {
            wrapper = WrapperUtils.CreateWrapper(name, key);
            algorithmIdentifier = nameToAlgo[name]();
        }


        public PkixKeyWrapper(IKeyWrapper<FipsRsa.OaepWrapParameters> wrapper, AlgorithmIdentifier algorithmIdentifier)
        {
            this.wrapper = wrapper;
            this.algorithmIdentifier = algorithmIdentifier;
        }

        public AlgorithmIdentifier AlgorithmDetails
        {
            get { return algorithmIdentifier; }
        }

        public IBlockResult Wrap(byte[] keyData)
        {
            return wrapper.Wrap(keyData);
        }
    }
}