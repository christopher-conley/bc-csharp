using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Tls.Core
{
    internal class AsymmetricKeyFactory
    {
        internal static IAsymmetricPublicKey CreatePublicKey(byte[] encodedPublicKeyInfo)
        {
            return CreatePublicKey(SubjectPublicKeyInfo.GetInstance(encodedPublicKeyInfo));
        }

        internal static IAsymmetricPublicKey CreatePublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo)
        {
            AlgorithmIdentifier algID = subjectPublicKeyInfo.AlgorithmID;
            DerObjectIdentifier algOid = algID.Algorithm;

            if (algOid.Equals(PkcsObjectIdentifiers.IdRsassaPss) ||
                algOid.Equals(PkcsObjectIdentifiers.IdRsaesOaep))
            {
                return new AsymmetricRsaPublicKey(FipsRsa.Alg, subjectPublicKeyInfo.GetEncoded());
            }

            return Security.AsymmetricKeyFactory.CreatePublicKey(subjectPublicKeyInfo.GetEncoded());
        }

        public static IAsymmetricPrivateKey CreatePrivateKey(byte[] encodedPrivateKeyInfo)
        {
            return CreatePrivateKey(PrivateKeyInfo.GetInstance(encodedPrivateKeyInfo));
        }

        internal static IAsymmetricPrivateKey CreatePrivateKey(PrivateKeyInfo privateKeyInfo)
        {
            AlgorithmIdentifier algID = privateKeyInfo.PrivateKeyAlgorithm;
            DerObjectIdentifier algOid = algID.Algorithm;

            if (algOid.Equals(PkcsObjectIdentifiers.IdRsassaPss) ||
                algOid.Equals(PkcsObjectIdentifiers.IdRsaesOaep))
            {
                return new AsymmetricRsaPrivateKey(FipsRsa.Alg, privateKeyInfo.GetEncoded());
            }

            return Security.AsymmetricKeyFactory.CreatePrivateKey(privateKeyInfo.GetEncoded());
        }
    }
}
