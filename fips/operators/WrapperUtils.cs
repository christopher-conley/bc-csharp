using System;
using System.Collections.Generic;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;

namespace Org.BouncyCastle.Operators
{
    public class WrapperUtils
    {

        internal readonly static IDictionary<String, Func<IAsymmetricPublicKey, IKeyWrapper<FipsRsa.OaepWrapParameters>>> wrappers = new Dictionary<string, Func<IAsymmetricPublicKey, IKeyWrapper<FipsRsa.OaepWrapParameters>>>();

        internal readonly static IDictionary<String, Func<IAsymmetricPrivateKey, IKeyUnwrapper<FipsRsa.OaepWrapParameters>>> unWrappers = new Dictionary<string, Func<IAsymmetricPrivateKey, IKeyUnwrapper<FipsRsa.OaepWrapParameters>>>();


        static WrapperUtils()
        {
            wrappers["RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING"] = delegate (IAsymmetricPublicKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPublicKey)key)
                       .CreateKeyWrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha1));
            };

            wrappers["RSA/NONE/OAEPWITHSHA224ANDMGF1PADDING"] = delegate (IAsymmetricPublicKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPublicKey)key)
                    .CreateKeyWrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha224));
            };

            wrappers["RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING"] = delegate (IAsymmetricPublicKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPublicKey)key)
                    .CreateKeyWrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha256));
            };

            wrappers["RSA/NONE/OAEPWITHSHA384ANDMGF1PADDING"] = delegate (IAsymmetricPublicKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPublicKey)key)
                    .CreateKeyWrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha384));
            };

            wrappers["RSA/NONE/OAEPWITHSHA512ANDMGF1PADDING"] = delegate (IAsymmetricPublicKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPublicKey)key)
                    .CreateKeyWrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha512));
            };


            //
            // Unwrappers
            //

            unWrappers["RSA/NONE/OAEPWITHSHA1ANDMGF1PADDING"] = delegate (IAsymmetricPrivateKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPrivateKey)key)
                    .CreateKeyUnwrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha1));
            };

            unWrappers["RSA/NONE/OAEPWITHSHA224ANDMGF1PADDING"] = delegate (IAsymmetricPrivateKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPrivateKey)key)
                    .CreateKeyUnwrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha224));
            };

            unWrappers["RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING"] = delegate (IAsymmetricPrivateKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPrivateKey)key)
                    .CreateKeyUnwrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha256));
            };

            unWrappers["RSA/NONE/OAEPWITHSHA384ANDMGF1PADDING"] = delegate (IAsymmetricPrivateKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPrivateKey)key)
                    .CreateKeyUnwrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha384));
            };

            unWrappers["RSA/NONE/OAEPWITHSHA512ANDMGF1PADDING"] = delegate (IAsymmetricPrivateKey key)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPrivateKey)key)
                    .CreateKeyUnwrapper(FipsRsa.WrapOaep.WithDigest(FipsShs.Sha512));
            };
        }


        public static IKeyWrapper<FipsRsa.OaepWrapParameters> CreateWrapper(String name, X509Certificate cert)
        {
            return wrappers[name](cert.GetPublicKey());
        }

        public static IKeyWrapper<FipsRsa.OaepWrapParameters> CreateWrapper(String name, IAsymmetricPublicKey pubKey)
        {
            return wrappers[name](pubKey);
        }    

        public static IKeyUnwrapper<FipsRsa.OaepWrapParameters> CreateUnWrapper(String name, IAsymmetricPrivateKey privKey)
        {
            return unWrappers[name](privKey);
        }


        //IKeyWrapper<FipsRsa.OaepWrapParameters>
    }
}