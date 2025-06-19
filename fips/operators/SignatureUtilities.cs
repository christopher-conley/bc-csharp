using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Operators
{
    /// <summary>
    ///  Signer Utility class contains methods that can not be specifically grouped into other classes.
    /// </summary>
    public sealed class SignatureUtilities
    {
        private SignatureUtilities()
        {
        }

        internal static readonly IDictionary algorithms = Platform.CreateHashtable();
        internal static readonly IDictionary oids = Platform.CreateHashtable();
        internal static readonly IDictionary<
            string,
            Func<IAsymmetricPrivateKey,object,
                ISignatureFactory<IParameters<Algorithm>>>> signatureBuilders = 
            new Dictionary<string, Func<IAsymmetricPrivateKey,object, ISignatureFactory<IParameters<Algorithm>>>>();

        internal static readonly IDictionary<
            string,
            Func<IAsymmetricPublicKey, object,
                IVerifierFactory<IParameters<Algorithm>>>> verifierBuilders =
            new Dictionary<string, Func<IAsymmetricPublicKey, object, IVerifierFactory<IParameters<Algorithm>>>>();


        static SignatureUtilities()
        {
            algorithms["MD2WITHRSA"] = "MD2withRSA";
            algorithms["MD2WITHRSAENCRYPTION"] = "MD2withRSA";
            algorithms[PkcsObjectIdentifiers.MD2WithRsaEncryption.Id] = "MD2withRSA";

            algorithms["MD4WITHRSA"] = "MD4withRSA";
            algorithms["MD4WITHRSAENCRYPTION"] = "MD4withRSA";
            algorithms[PkcsObjectIdentifiers.MD4WithRsaEncryption.Id] = "MD4withRSA";

            algorithms["MD5WITHRSA"] = "MD5withRSA";
            algorithms["MD5WITHRSAENCRYPTION"] = "MD5withRSA";
            algorithms[PkcsObjectIdentifiers.MD5WithRsaEncryption.Id] = "MD5withRSA";

            const string sha1WithRSA= "SHA-1withRSA";

            algorithms["SHA1WITHRSA"] = sha1WithRSA;
            algorithms["SHA1WITHRSAENCRYPTION"] = sha1WithRSA;
            algorithms[PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id] = sha1WithRSA;
            algorithms["SHA-1WITHRSA"] = sha1WithRSA;

            const string sha224WithRSA = "SHA-224withRSA";
            algorithms["SHA224WITHRSA"] = sha224WithRSA;
            algorithms["SHA224WITHRSAENCRYPTION"] = sha224WithRSA;
            algorithms[PkcsObjectIdentifiers.Sha224WithRsaEncryption.Id] = sha224WithRSA;
            algorithms["SHA-224WITHRSA"] = sha224WithRSA;

            const string sha256WithRSA = "SHA-256withRSA";
            algorithms["SHA256WITHRSA"] = sha256WithRSA;
            algorithms["SHA256WITHRSAENCRYPTION"] = sha256WithRSA;
            algorithms[PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id] = sha256WithRSA;
            algorithms["SHA-256WITHRSA"] = sha256WithRSA;


            const string sha384WithRSA = "SHA-384withRSA";
            algorithms["SHA384WITHRSA"] = sha384WithRSA;
            algorithms["SHA384WITHRSAENCRYPTION"] = sha384WithRSA;
            algorithms[PkcsObjectIdentifiers.Sha384WithRsaEncryption.Id] = sha384WithRSA;
            algorithms["SHA-384WITHRSA"] = sha384WithRSA;

            const string sha512WithRSA = "SHA-512withRSA";
            algorithms["SHA512WITHRSA"] = sha512WithRSA;
            algorithms["SHA512WITHRSAENCRYPTION"] = sha512WithRSA;
            algorithms[PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id] = sha512WithRSA;
            algorithms["SHA-512WITHRSA"] = sha512WithRSA;

            const string pssWithRSA = "PSSwithRSA";
            algorithms["PSSWITHRSA"] = pssWithRSA;
            algorithms["RSASSA-PSS"] = pssWithRSA;
            algorithms[PkcsObjectIdentifiers.IdRsassaPss.Id] = pssWithRSA;
            algorithms["RSAPSS"] = pssWithRSA;

            const string sha1WithRSAandMGF1 = "SHA-1withRSAandMGF1";
            algorithms["SHA1WITHRSAANDMGF1"] = sha1WithRSAandMGF1;
            algorithms["SHA-1WITHRSAANDMGF1"] = sha1WithRSAandMGF1;
            algorithms["SHA1WITHRSA/PSS"] = sha1WithRSAandMGF1;
            algorithms["SHA-1WITHRSA/PSS"] = sha1WithRSAandMGF1;

            const string sha224WithRsaAndMGF1 = "SHA-224withRSAandMGF1";

            algorithms["SHA224WITHRSAANDMGF1"] = sha224WithRsaAndMGF1;
            algorithms["SHA-224WITHRSAANDMGF1"] = sha224WithRsaAndMGF1;
            algorithms["SHA224WITHRSA/PSS"] = sha224WithRsaAndMGF1;
            algorithms["SHA-224WITHRSA/PSS"] = sha224WithRsaAndMGF1;

            const string sha256WithRsaAndMGF1 = "SHA-256withRSAandMGF1";
            algorithms["SHA256WITHRSAANDMGF1"] = sha256WithRsaAndMGF1;
            algorithms["SHA-256WITHRSAANDMGF1"] = sha256WithRsaAndMGF1;
            algorithms["SHA256WITHRSA/PSS"] = sha256WithRsaAndMGF1;
            algorithms["SHA-256WITHRSA/PSS"] = sha256WithRsaAndMGF1;
        
            const string sha384WithRsaAndMGF1 = "SHA-384withRSAandMGF1";
            algorithms["SHA384WITHRSAANDMGF1"] = sha384WithRsaAndMGF1;
            algorithms["SHA-384WITHRSAANDMGF1"] = sha384WithRsaAndMGF1;
            algorithms["SHA384WITHRSA/PSS"] = sha384WithRsaAndMGF1;
            algorithms["SHA-384WITHRSA/PSS"] = sha384WithRsaAndMGF1;


            const string sha512WithRsaAndMGF1 = "SHA-512withRSAandMGF1";
            algorithms["SHA512WITHRSAANDMGF1"] = sha512WithRsaAndMGF1;
            algorithms["SHA-512WITHRSAANDMGF1"] = sha512WithRsaAndMGF1;
            algorithms["SHA512WITHRSA/PSS"] = sha512WithRsaAndMGF1;
            algorithms["SHA-512WITHRSA/PSS"] = sha512WithRsaAndMGF1;

            algorithms["RIPEMD128WITHRSA"] = "RIPEMD128withRSA";
            algorithms["RIPEMD128WITHRSAENCRYPTION"] = "RIPEMD128withRSA";
            algorithms[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128.Id] = "RIPEMD128withRSA";

            algorithms["RIPEMD160WITHRSA"] = "RIPEMD160withRSA";
            algorithms["RIPEMD160WITHRSAENCRYPTION"] = "RIPEMD160withRSA";
            algorithms[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160.Id] = "RIPEMD160withRSA";

            algorithms["RIPEMD256WITHRSA"] = "RIPEMD256withRSA";
            algorithms["RIPEMD256WITHRSAENCRYPTION"] = "RIPEMD256withRSA";
            algorithms[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256.Id] = "RIPEMD256withRSA";

            algorithms["NONEWITHRSA"] = "RSA";
            algorithms["RSAWITHNONE"] = "RSA";
            algorithms["RAWRSA"] = "RSA";

            algorithms["RAWRSAPSS"] = "RAWRSASSA-PSS";
            algorithms["NONEWITHRSAPSS"] = "RAWRSASSA-PSS";
            algorithms["NONEWITHRSASSA-PSS"] = "RAWRSASSA-PSS";

            algorithms["NONEWITHDSA"] = "NONEwithDSA";
            algorithms["DSAWITHNONE"] = "NONEwithDSA";
            algorithms["RAWDSA"] = "NONEwithDSA";


            const string sha1WithDSA = "SHA-1withDSA";
            algorithms["DSA"] = sha1WithDSA;
            algorithms["DSAWITHSHA1"] = sha1WithDSA;
            algorithms["DSAWITHSHA-1"] = sha1WithDSA;
            algorithms["SHA/DSA"] = sha1WithDSA;
            algorithms["SHA1/DSA"] = sha1WithDSA;
            algorithms["SHA-1/DSA"] = sha1WithDSA;
            algorithms["SHA1WITHDSA"] = sha1WithDSA;
            algorithms["SHA-1WITHDSA"] = sha1WithDSA;
            algorithms[X9ObjectIdentifiers.IdDsaWithSha1.Id] = sha1WithDSA;

            const string sha224WithDSA= "SHA-224withDSA";

            algorithms["DSAWITHSHA224"] = sha224WithDSA;
            algorithms["DSAWITHSHA-224"] = sha224WithDSA;
            algorithms["SHA224/DSA"] = sha224WithDSA;
            algorithms["SHA-224/DSA"] = sha224WithDSA;
            algorithms["SHA224WITHDSA"] = sha224WithDSA;
            algorithms["SHA-224WITHDSA"] = sha224WithDSA;
            algorithms[NistObjectIdentifiers.DsaWithSha224.Id] = sha224WithDSA;

            const string sha256WithDSA= "SHA-256withDSA";
            algorithms["DSAWITHSHA256"] = sha256WithDSA;
            algorithms["DSAWITHSHA-256"] = sha256WithDSA;
            algorithms["SHA256/DSA"] = sha256WithDSA;
            algorithms["SHA-256/DSA"] = sha256WithDSA;
            algorithms["SHA256WITHDSA"] = sha256WithDSA;
            algorithms["SHA-256WITHDSA"] = sha256WithDSA;
            algorithms[NistObjectIdentifiers.DsaWithSha256.Id] = sha256WithDSA;

            const string sha384WithDSA = "SHA-384withDSA";
            algorithms["DSAWITHSHA384"] = sha384WithDSA;
            algorithms["DSAWITHSHA-384"] = sha384WithDSA;
            algorithms["SHA384/DSA"] = sha384WithDSA;
            algorithms["SHA-384/DSA"] = sha384WithDSA;
            algorithms["SHA384WITHDSA"] = sha384WithDSA;
            algorithms["SHA-384WITHDSA"] = sha384WithDSA;
            algorithms[NistObjectIdentifiers.DsaWithSha384.Id] = sha384WithDSA;

            const string sha512WithDSA = "SHA-512withDSA";            
            algorithms["DSAWITHSHA512"] = sha512WithDSA;
            algorithms["DSAWITHSHA-512"] = sha512WithDSA;
            algorithms["SHA512/DSA"] = sha512WithDSA;
            algorithms["SHA-512/DSA"] = sha512WithDSA;
            algorithms["SHA512WITHDSA"] = sha512WithDSA;
            algorithms["SHA-512WITHDSA"] = sha512WithDSA;
            algorithms[NistObjectIdentifiers.DsaWithSha512.Id] = sha512WithDSA;

            algorithms["NONEWITHECDSA"] = "NONEwithECDSA";
            algorithms["ECDSAWITHNONE"] = "NONEwithECDSA";


            const string sha1WithECDSA = "SHA-1withECDSA";
            algorithms["ECDSA"] = sha1WithECDSA;
            algorithms["SHA1/ECDSA"] = sha1WithECDSA;
            algorithms["SHA-1/ECDSA"] = sha1WithECDSA;
            algorithms["ECDSAWITHSHA1"] = sha1WithECDSA;
            algorithms["ECDSAWITHSHA-1"] = sha1WithECDSA;
            algorithms["SHA1WITHECDSA"] = sha1WithECDSA;
            algorithms["SHA-1WITHECDSA"] = sha1WithECDSA;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha1.Id] = sha1WithECDSA;
            algorithms[TeleTrusTObjectIdentifiers.ECSignWithSha1.Id] = sha1WithECDSA;

            const string sha224WithECDSA = "SHA-224withECDSA";

            algorithms["SHA224/ECDSA"] = sha224WithECDSA;
            algorithms["SHA-224/ECDSA"] = sha224WithECDSA;
            algorithms["ECDSAWITHSHA224"] = sha224WithECDSA;
            algorithms["ECDSAWITHSHA-224"] = sha224WithECDSA;
            algorithms["SHA224WITHECDSA"] = sha224WithECDSA;
            algorithms["SHA-224WITHECDSA"] = sha224WithECDSA;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha224.Id] = sha224WithECDSA;

            const string sha256WithECDSA = "SHA-256withECDSA";
            algorithms["SHA256/ECDSA"] = sha256WithECDSA;
            algorithms["SHA-256/ECDSA"] = sha256WithECDSA;
            algorithms["ECDSAWITHSHA256"] = sha256WithECDSA;
            algorithms["ECDSAWITHSHA-256"] = sha256WithECDSA;
            algorithms["SHA256WITHECDSA"] = sha256WithECDSA;
            algorithms["SHA-256WITHECDSA"] = sha256WithECDSA;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha256.Id] = sha256WithECDSA;

            const string sha384WithECDSA = "SHA-384withECDSA";
            algorithms["SHA384/ECDSA"] = sha384WithECDSA;
            algorithms["SHA-384/ECDSA"] = sha384WithECDSA;
            algorithms["ECDSAWITHSHA384"] = sha384WithECDSA;
            algorithms["ECDSAWITHSHA-384"] = sha384WithECDSA;
            algorithms["SHA384WITHECDSA"] = sha384WithECDSA;
            algorithms["SHA-384WITHECDSA"] = sha384WithECDSA;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha384.Id] = sha384WithECDSA;

            const string sha512WithECDSA = "SHA-512withECDSA";
            algorithms["SHA512/ECDSA"] = sha512WithECDSA;
            algorithms["SHA-512/ECDSA"] = sha512WithECDSA;
            algorithms["ECDSAWITHSHA512"] = sha512WithECDSA;
            algorithms["ECDSAWITHSHA-512"] = sha512WithECDSA;
            algorithms["SHA512WITHECDSA"] = sha512WithECDSA;
            algorithms["SHA-512WITHECDSA"] = sha512WithECDSA;
            algorithms[X9ObjectIdentifiers.ECDsaWithSha512.Id] = sha512WithECDSA;


            algorithms["RIPEMD160/ECDSA"] = "RIPEMD160withECDSA";
            algorithms["ECDSAWITHRIPEMD160"] = "RIPEMD160withECDSA";
            algorithms["RIPEMD160WITHECDSA"] = "RIPEMD160withECDSA";
            algorithms[TeleTrusTObjectIdentifiers.ECSignWithRipeMD160.Id] = "RIPEMD160withECDSA";


            algorithms["GOST-3410"] = "GOST3410";
            algorithms["GOST-3410-94"] = "GOST3410";
            algorithms["GOST3411WITHGOST3410"] = "GOST3410";
            algorithms[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94.Id] = "GOST3410";


            algorithms["ECGOST-3410"] = "ECGOST3410";
            algorithms["ECGOST-3410-2001"] = "ECGOST3410";
            algorithms["GOST3411WITHECGOST3410"] = "ECGOST3410";
            algorithms[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001.Id] = "ECGOST3410";



            oids["MD2withRSA"] = PkcsObjectIdentifiers.MD2WithRsaEncryption;
            oids["MD4withRSA"] = PkcsObjectIdentifiers.MD4WithRsaEncryption;
            oids["MD5withRSA"] = PkcsObjectIdentifiers.MD5WithRsaEncryption;

            oids["SHA-1withRSA"] = PkcsObjectIdentifiers.Sha1WithRsaEncryption;
            oids["SHA-224withRSA"] = PkcsObjectIdentifiers.Sha224WithRsaEncryption;
            oids["SHA-256withRSA"] = PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            oids["SHA-384withRSA"] = PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            oids["SHA-512withRSA"] = PkcsObjectIdentifiers.Sha512WithRsaEncryption;

            oids["PSSwithRSA"] = PkcsObjectIdentifiers.IdRsassaPss;
            oids["SHA-1withRSAandMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            oids["SHA-224withRSAandMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            oids["SHA-256withRSAandMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            oids["SHA-384withRSAandMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;
            oids["SHA-512withRSAandMGF1"] = PkcsObjectIdentifiers.IdRsassaPss;

            oids["RIPEMD128withRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
            oids["RIPEMD160withRSA"] = TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
        
            oids["SHA-1withDSA"] = X9ObjectIdentifiers.IdDsaWithSha1;

            oids["SHA-1withECDSA"] = X9ObjectIdentifiers.ECDsaWithSha1;
            oids["SHA-224withECDSA"] = X9ObjectIdentifiers.ECDsaWithSha224;
            oids["SHA-256withECDSA"] = X9ObjectIdentifiers.ECDsaWithSha256;
            oids["SHA-384withECDSA"] = X9ObjectIdentifiers.ECDsaWithSha384;
            oids["SHA-512withECDSA"] = X9ObjectIdentifiers.ECDsaWithSha512;

            oids["GOST3410"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;
            oids["ECGOST3410"] = CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;



            signatureBuilders[sha1WithDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricDsaPrivateKey)key).CreateSignatureFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha1));
            };

            signatureBuilders[sha224WithDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricDsaPrivateKey)key).CreateSignatureFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha224));
            };

            signatureBuilders[sha256WithDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricDsaPrivateKey)key).CreateSignatureFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha256));
            };

            signatureBuilders[sha384WithDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricDsaPrivateKey)key).CreateSignatureFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha384));
            };

            signatureBuilders[sha512WithDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricDsaPrivateKey)key).CreateSignatureFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha512));
            };


            //
            // XXXwithRSAEncryption.
            //
            signatureBuilders[sha1WithRSA] = delegate(IAsymmetricPrivateKey key, object param)
                {                
                   return  CryptoServicesRegistrar.CreateService((AsymmetricRsaPrivateKey)key).CreateSignatureFactory(FipsRsa.Pkcs1v15
                        .WithDigest(FipsShs.Sha1));
                    };

            signatureBuilders[sha224WithRSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar
                    .CreateService((AsymmetricRsaPrivateKey)key)
                    .CreateSignatureFactory(FipsRsa.Pkcs1v15
                    .WithDigest(FipsShs.Sha224));
            };

            signatureBuilders[sha256WithRSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar
                    .CreateService((AsymmetricRsaPrivateKey)key)
                    .CreateSignatureFactory(FipsRsa.Pkcs1v15
                        .WithDigest(FipsShs.Sha256));
            };

            signatureBuilders[sha384WithRSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar
                    .CreateService((AsymmetricRsaPrivateKey)key)
                    .CreateSignatureFactory(FipsRsa.Pkcs1v15
                        .WithDigest(FipsShs.Sha384));
            };
            
            signatureBuilders[sha512WithRSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar
                    .CreateService((AsymmetricRsaPrivateKey)key)
                    .CreateSignatureFactory(FipsRsa.Pkcs1v15
                        .WithDigest(FipsShs.Sha512));
            };

            // PSSxxxWithRSA

            signatureBuilders[pssWithRSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                if (param is FipsRsa.PssSignatureParameters)
                {
                    FipsRsa.PssSignatureParameters pssParameters = (FipsRsa.PssSignatureParameters)param;

                    return CryptoServicesRegistrar.CreateService((AsymmetricECPrivateKey)key)
                        .CreateSignatureFactory(pssParameters);
                } 

                throw new ArgumentException("parameters are not FipsRsa.PssSignatureParameters");                
            };

           
            // ECDsaWithXXX
            signatureBuilders[sha1WithECDSA] = delegate(IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPrivateKey) key)
                    .CreateSignatureFactory(EC.DDsa.WithDigest(FipsShs.Sha1));
            };

            signatureBuilders[sha224WithECDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPrivateKey)key)
                    .CreateSignatureFactory(EC.DDsa.WithDigest(FipsShs.Sha224));
            };

            signatureBuilders[sha256WithECDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPrivateKey)key)
                    .CreateSignatureFactory(EC.DDsa.WithDigest(FipsShs.Sha256));
            };

            signatureBuilders[sha384WithECDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPrivateKey)key)
                    .CreateSignatureFactory(EC.DDsa.WithDigest(FipsShs.Sha384));
            };

            signatureBuilders[sha512WithECDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPrivateKey)key)
                    .CreateSignatureFactory(EC.DDsa.WithDigest(FipsShs.Sha256));
            };

           


            // Verifier.


            verifierBuilders[sha1WithDSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar. CreateService((AsymmetricDsaPublicKey)key).CreateVerifierFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha1));
            };

            verifierBuilders[sha224WithDSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricDsaPublicKey)key).CreateVerifierFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha224));
            };


            verifierBuilders[sha256WithDSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricDsaPublicKey)key).CreateVerifierFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha256));
            };

            signatureBuilders[sha384WithDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPrivateKey)key).CreateSignatureFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha384));
            };

            signatureBuilders[sha512WithDSA] = delegate (IAsymmetricPrivateKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPrivateKey)key).CreateSignatureFactory(FipsDsa.Dsa
                    .WithDigest(FipsShs.Sha512));
            };


          

            //
            // XXXwithRSAEncryption.
            //
            verifierBuilders[sha1WithRSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricRsaPublicKey)key).CreateVerifierFactory(FipsRsa.Pkcs1v15
                     .WithDigest(FipsShs.Sha1));
            };

            verifierBuilders[sha224WithRSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar
                    .CreateService((AsymmetricRsaPublicKey)key)
                    .CreateVerifierFactory(FipsRsa.Pkcs1v15
                    .WithDigest(FipsShs.Sha224));
            };

            verifierBuilders[sha256WithRSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar
                    .CreateService((AsymmetricRsaPublicKey)key)
                    .CreateVerifierFactory(FipsRsa.Pkcs1v15
                        .WithDigest(FipsShs.Sha256));
            };

            verifierBuilders[sha384WithRSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar
                    .CreateService((AsymmetricRsaPublicKey)key)
                    .CreateVerifierFactory(FipsRsa.Pkcs1v15
                        .WithDigest(FipsShs.Sha384));
            };

            verifierBuilders[sha512WithRSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar
                    .CreateService((AsymmetricRsaPublicKey)key)
                    .CreateVerifierFactory(FipsRsa.Pkcs1v15
                        .WithDigest(FipsShs.Sha512));
            };

            // PSSxxxWithRSA

            verifierBuilders[pssWithRSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                if (param is FipsRsa.PssSignatureParameters)
                {
                    return CryptoServicesRegistrar.CreateService((AsymmetricRsaPublicKey)key)
                        .CreateVerifierFactory((FipsRsa.PssSignatureParameters)param);
                }

                throw new ArgumentException("parameters are not FipsRsa.PssSignatureParameters");
            };





            // ECDsaWithXXX
            verifierBuilders[sha1WithECDSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPublicKey)key)
                    .CreateVerifierFactory(EC.DDsa.WithDigest(FipsShs.Sha1));
            };

            verifierBuilders[sha224WithECDSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPublicKey)key)
                    .CreateVerifierFactory(EC.DDsa.WithDigest(FipsShs.Sha224));
            };

            verifierBuilders[sha256WithECDSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPublicKey)key)
                    .CreateVerifierFactory(EC.DDsa.WithDigest(FipsShs.Sha256));
            };

            verifierBuilders[sha384WithECDSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPublicKey)key)
                    .CreateVerifierFactory(EC.DDsa.WithDigest(FipsShs.Sha384));
            };

            verifierBuilders[sha512WithECDSA] = delegate (IAsymmetricPublicKey key, object param)
            {
                return CryptoServicesRegistrar.CreateService((AsymmetricECPublicKey)key)
                    .CreateVerifierFactory(EC.DDsa.WithDigest(FipsShs.Sha256));
            };

                 
        }


        public static ISignatureFactory<IParameters<Algorithm>> CreateSignatureFactory(
            DerObjectIdentifier oid, IAsymmetricPrivateKey privateKey, object parameters)
        {
           if (oid == null ) { throw new ArgumentException("oid is null");}

            if (privateKey == null)
            {
                throw new ArgumentException("privateKey is null");
            }

            return CreateSignatureFactory(oid.Id, privateKey, parameters);
        }

        public static ISignatureFactory<IParameters<Algorithm>> CreateSignatureFactory(
            String name, IAsymmetricPrivateKey privateKey, object parameters)
        {
            if (name == null) { throw new ArgumentException("name is null"); }

            if (privateKey == null)
            {
                throw new ArgumentException("privateKey is null");
            }

            var resolvedName = name.ToUpper();

            if (algorithms.Contains(resolvedName))
            {
                resolvedName = algorithms[resolvedName].ToString();
            }

            if (signatureBuilders.ContainsKey(resolvedName))
            {
                return signatureBuilders[resolvedName](privateKey, parameters);
            }
            throw new InvalidOperationException("could not resolve signature name: '"+name + "' resolved as '"+resolvedName+"'");
        }



        public static IVerifierFactory<IParameters<Algorithm>> CreateVerifierFactory(
            DerObjectIdentifier oid, IAsymmetricPublicKey publicKey, object parameters)
        {
            if (oid == null) { throw new ArgumentException("oid is null"); }

            if (publicKey == null)
            {
                throw new ArgumentException("publicKey is null");
            }

            return CreateVerifierFactory(oid.Id, publicKey, parameters);
        }

        public static IVerifierFactory<IParameters<Algorithm>> CreateVerifierFactory(
            String name, IAsymmetricPublicKey publicKey, object parameters)
        {
            if (name == null) { throw new ArgumentException("name is null"); }

           
            if (publicKey == null)
            {
                throw new ArgumentException("publicKey is null");
            }

            var resolvedName = name.ToUpper();

            if (algorithms.Contains(resolvedName))
            {
                resolvedName = algorithms[resolvedName].ToString();
            }

            if (verifierBuilders.ContainsKey(resolvedName))
            {
                return verifierBuilders[resolvedName](publicKey, parameters);
            }
            throw new InvalidOperationException("could not resolve signature name: '" + name + "' resolved as '" + resolvedName + "'");
        }






        public static ICollection Algorithms
        {
            get { return oids.Keys; }
        }

        public static string GetAlgorithmName(
            AlgorithmIdentifier algID)
        {          
            return (string) algorithms[algID.Algorithm.Id];
        }

        public static ISignatureFactory<IParameters<Algorithm>> CreateFactory(string sigalg)
        {
            return null;
        }

        public static ISignatureFactory<IParameters<Algorithm>> CreateFactory(DerObjectIdentifier sigalg)
        {
            return null;
        }

        public static ISignatureFactory<IParameters<Algorithm>> CreateFactory(object sigalg)
        {
            return null;
        }


    }
}
