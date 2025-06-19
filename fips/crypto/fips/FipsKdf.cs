using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Digests;
using Org.BouncyCastle.Crypto.Internal.Generators;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for FIPS approved Key Derivation Function (KDF) implementations.
    /// </summary>
    public class FipsKdf
    {
        /// <summary>
        /// Parameters configuration for ASN X9.63-2001
        /// </summary>
        public static readonly AgreementKdfBuilderService X963 = new AgreementKdfBuilderService(new FipsAlgorithm("X9.63"));

        /// <summary>
        /// Algorithm marker for concatenating KDF in FIPS SP 800-56C
        /// </summary>
        public static readonly AgreementKdfBuilderService Concatenation = new AgreementKdfBuilderService(new FipsAlgorithm("Concatenation"));

        /// <summary>
        /// Algorithm key builder for HKDF service in RFC 5869, FIPS SP 800-56C
        /// </summary>
        public static readonly HKdfKeyBuilder HKdfKeyBldr = new HKdfKeyBuilder(new FipsAlgorithm("HKDF"), FipsPrfAlgorithm.Sha256, null, false);

        /// <summary>
        /// Algorithm marker for Transport Layer Security Version 1.0 (TLSv1.0)
        /// </summary>
        public static readonly TlsKdfBuilderService Tls1_0 = new TlsKdfBuilderService(new FipsAlgorithm("TLS1.0"));

        /// <summary>
        /// Algorithm marker for Transport Layer Security Version 1.1 (TLSv1.1)
        /// </summary>
        public static readonly TlsKdfBuilderService Tls1_1 = new TlsKdfBuilderService(new FipsAlgorithm("TLS1.1"));

        /// <summary>
        /// Algorithm marker for Transport Layer Security Version 1.2 (TLSv1.2)
        /// </summary>
        public static readonly TlsKdfWithPrfBuilderService Tls1_2 = new TlsKdfWithPrfBuilderService(new FipsAlgorithm("TLS1.2"));

        private readonly static MD5Provider md5Provider = new MD5Provider();

        static FipsKdf()
        {
            // FSM_STATE:3.KDF.0, TLS 1.0 KAT, "The module is performing the KAT test for the MD5 digest in TLS 1.0"
            // FSM_TRANS:3.KDF.0, "POWER ON SELF-TEST",	"TLS 1.0 KDF GENERATE VERIFY KAT",	"Invoke MD5 digest in TLS 1.0 KDF Generate/Verify KAT self-test"
            md5Provider.CreateEngine(EngineUsage.GENERAL);
            // FSM_TRANS:3.KDF.1, "TLS 1.0 KDF GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"MD5 digest in TLS 1.0 KDF KAT self-test successful completion"

            // FSM_STATE:3.SP800-56C.0,"SP800-56C KDF GENERATE KAT", "The module is performing SP800-56C KDF generate KAT self-test"
            // FSM_TRANS:3.SP800-56C.0.0,"POWER ON SELF-TEST", "SP800-56C KDF GENERATE KAT",	"Invoke SP800-56C KDF Generate KAT self-test"
            new ConcatenationKdfProvider(FipsPrfAlgorithm.Sha256).CreateEngine(EngineUsage.GENERAL);
            new ConcatenationKdfProvider(FipsPrfAlgorithm.Sha256HMac).CreateEngine(EngineUsage.GENERAL);
            new ConcatenationKdfProvider(FipsPrfAlgorithm.KMac256).CreateEngine(EngineUsage.GENERAL);
      
            new HKdfProvider(FipsPrfAlgorithm.Sha256HMac).CreateEngine(EngineUsage.GENERAL);
            // FSM_TRANS:3.SP800-56C.0.1, "SP800-56C KDF GENERATE KAT", "POWER ON SELF-TEST", "SP800-56C KDF Generate KAT self-test successful completion"

            // FSM_STATE:3.ASKDF.0,"SP800-135 KDF GENERATE KAT", "The module is performing SP800-135 KDF generate KAT self-test"
            // FSM_TRANS:3.ASKDF.0.0,"POWER ON SELF-TEST", "SP800-135 KDF GENERATE KAT", "Invoke SP800-135 KDF Generate KAT self-test"
            new X963KdfProvider(FipsPrfAlgorithm.Sha256).CreateEngine(EngineUsage.GENERAL);
            TlsLegacyKat();   // full KAT test - not just MD5
            Tls1_1and2Kat();
            // FSM_TRANS:3.ASKDF.0.1, "SP800-135 KDF GENERATE KAT", "POWER ON SELF-TEST", "SP800-135 KDF Generate KAT self-test successful completion"
        }

        public class AgreementKdfBuilderService : Parameters<FipsAlgorithm>, IBuilderServiceType<AgreementKdfBuilder>, IBuilderService<AgreementKdfBuilder>
        {
            internal AgreementKdfBuilderService(FipsAlgorithm algorithm) : base(algorithm)
            {

            }

            Func<IParameters<Algorithm>, AgreementKdfBuilder> IBuilderService<AgreementKdfBuilder>.GetFunc(SecurityContext context)
            {
                return (parameters) => new AgreementKdfBuilder((FipsAlgorithm)parameters.Algorithm, FipsPrfAlgorithm.Sha1, null, null);
            }
        }

        public class AgreementKdfBuilder
        {
            private readonly FipsAlgorithm algorithm;
            private readonly FipsPrfAlgorithm prf;
            private readonly byte[] iv;
            private readonly byte[] salt;

            internal AgreementKdfBuilder(FipsAlgorithm algorithm, FipsPrfAlgorithm prf, byte[] iv, byte[] salt)
            {
                this.algorithm = algorithm;
                this.prf = prf;
                this.iv = iv;
                this.salt = salt;
            }

            public AgreementKdfBuilder WithPrf(FipsPrfAlgorithm prf)
            {
                return new AgreementKdfBuilder(algorithm, prf, iv, salt);
            }

            public AgreementKdfBuilder WithIV(byte[] iv)
            {
                return new AgreementKdfBuilder(algorithm, prf, Arrays.Clone(iv), salt);
            }

            public AgreementKdfBuilder WithSalt(byte[] salt)
            {
                return new AgreementKdfBuilder(algorithm, prf, iv, Arrays.Clone(salt));
            }
            public IKdfCalculator<AgreementKdfParameters> From(byte[] shared)
            {
                AgreementKdfParameters parameters = new AgreementKdfParameters(new FipsKdfAlgorithm(algorithm, prf), shared, salt, iv);

                if (parameters.Algorithm.Kdf == X963.Algorithm)
                {
                    IDerivationFunction df = new X963KdfProvider(parameters.Prf).CreateEngine(EngineUsage.GENERAL);

                    df.Init(new KdfParameters(parameters.GetShared(), parameters.GetIV()));

                    return new AgreementKdfCalculator(parameters, df);
                }
                else
                {
                    IDerivationFunction df = new ConcatenationKdfProvider(parameters.Prf).CreateEngine(EngineUsage.GENERAL);
                   
                    df.Init(new KdfParameters(parameters.GetShared(), parameters.GetSalt(), parameters.GetIV()));

                    return new AgreementKdfCalculator(parameters, df);
                }
            }
        }

        public class HKdfService
            : Parameters<FipsAlgorithm>, ICryptoServiceType<IKdfCalculator<AgreementKdfParameters>>,
                IServiceProvider<IKdfCalculator<AgreementKdfParameters>>
        {
            internal HKdfService()
                : base(new FipsAlgorithm("HKDF"))
            {
            }

            Func<IKey, IKdfCalculator<AgreementKdfParameters>>
                IServiceProvider<IKdfCalculator<AgreementKdfParameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new HKdfBuilder().From((HKdfKey)parameters);
            }
        }

        public class HKdfKey
            : HKdfService, IKey
        {
            private readonly FipsKdfAlgorithm algorithm;
            private readonly byte[] value;
            private readonly byte[] iv;
            private readonly byte[] salt;

            internal HKdfKey(FipsKdfAlgorithm algorithm, byte[] keyValue, byte[] salt, byte[] iv)
            {
                this.algorithm = algorithm;
                this.value = keyValue;
                this.iv = iv;
                this.salt = salt;
            }

            // TODO This is somewhat confusing API-wise since it hides Algorithm property from HKdfService
            public new Algorithm Algorithm
            {
                get { return algorithm; }
            }

            public byte[] GetKey()
            {
                return Arrays.Clone(value);
            }

            public byte[] GetIV()
            {
                return Arrays.Clone(iv);
            }

            public byte[] GetSalt()
            {
                return Arrays.Clone(value);
            }

            public HKdfKey WithIV(byte[] iv)
            {
                return new HKdfKey(algorithm, value, salt, Arrays.Clone(iv));
            }
        }

        public class HKdfKeyBuilder
        {
            private readonly FipsAlgorithm algorithm;
            private readonly FipsPrfAlgorithm prf;
            private readonly byte[] salt;
            private readonly bool skipExtract;

            internal HKdfKeyBuilder(FipsAlgorithm algorithm, FipsPrfAlgorithm prf, byte[] salt, bool skipExtract)
            {
                this.algorithm = algorithm;
                this.prf = prf;
                this.salt = salt;
                this.skipExtract = skipExtract;
            }

            public FipsKdfAlgorithm Algorithm
            {
                get { return new FipsKdfAlgorithm(algorithm, prf); }
            }

            public HKdfKeyBuilder SetSkipExtract(bool skipExtract)
            {
                return new HKdfKeyBuilder(algorithm, prf, salt, skipExtract);
            }

            public HKdfKeyBuilder WithSalt(byte[] salt)
            {
                return new HKdfKeyBuilder(algorithm, prf, Arrays.Clone(salt), skipExtract);
            }

            public HKdfKeyBuilder WithPrf(FipsPrfAlgorithm prf)
            {
                if (!FipsShs.IsHMac((DigestAlgorithm)prf.BaseAlgorithm))
                {
                    throw new ArgumentException("PRF not recognized for HKDF: " + prf);
                }

                return new HKdfKeyBuilder(algorithm, prf, salt, skipExtract);
            }

            public HKdfKey Build(byte[] ikm)
            {
                HMac mac = (HMac)FipsShs.CreateHmac((DigestAlgorithm)prf.BaseAlgorithm);
          
                return new HKdfKey(new FipsKdfAlgorithm(algorithm, prf), new HKdfKeyGenerator(mac).Generate(new HKdfKeyParameters(ikm, skipExtract, salt)).GetKey(), salt, ikm);
            }
        }

        internal class HKdfBuilder
        {
            internal HKdfBuilder()
            {
            }

            internal IKdfCalculator<AgreementKdfParameters> From(HKdfKey key)
            {
                FipsKdfAlgorithm kdfAlg = (FipsKdfAlgorithm)key.Algorithm;
                AgreementKdfParameters parameters = new AgreementKdfParameters(kdfAlg, key.GetKey(), key.GetSalt(), key.GetIV());
                HKdfParameters kdfParameters = new HKdfParameters(new KeyParameter(key.GetKey()), key.GetIV());
                IDerivationFunction df = new HKdfProvider((FipsPrfAlgorithm)kdfAlg.Prf).CreateEngine(EngineUsage.GENERAL);

                df.Init(kdfParameters);

                return new HKdfCalculator(parameters, df);
            }
        }

        public class TlsKdfBuilderService : Parameters<FipsAlgorithm>, IBuilderServiceType<TlsKdfBuilder>, IBuilderService<TlsKdfBuilder>
        {
            internal TlsKdfBuilderService(FipsAlgorithm algorithm) : base(algorithm)
            {

            }

            Func<IParameters<Algorithm>, TlsKdfBuilder> IBuilderService<TlsKdfBuilder>.GetFunc(SecurityContext context)
            {
                return (parameters) => new TlsKdfBuilder((FipsAlgorithm)parameters.Algorithm);
            }
        }

        /// <summary>
        /// Builder for the TLS 1.0 key derivation function.
        /// </summary>
        public class TlsKdfBuilder
        {
            private readonly FipsAlgorithm algorithm;

            internal TlsKdfBuilder(FipsAlgorithm algorithm)
            {
                this.algorithm = algorithm;
            }

            public IKdfCalculator<TlsKdfParameters> From(byte[] secret, string label, params byte[][] seedMaterial)
            {
                TlsKdfParameters parameters = new TlsKdfParameters(algorithm, Arrays.Clone(secret), label, Concatenate(seedMaterial));

                return new Tls10and11KdfFactory(parameters);
            }
        }

        public class TlsKdfWithPrfBuilderService : Parameters<FipsAlgorithm>, IBuilderServiceType<TlsKdfWithPrfBuilder>, IBuilderService<TlsKdfWithPrfBuilder>
        {
            internal TlsKdfWithPrfBuilderService(FipsAlgorithm algorithm) : base(algorithm)
            {

            }

            Func<IParameters<Algorithm>, TlsKdfWithPrfBuilder> IBuilderService<TlsKdfWithPrfBuilder>.GetFunc(SecurityContext context)
            {
                return (parameters) => new TlsKdfWithPrfBuilder((FipsAlgorithm)parameters.Algorithm, FipsShs.Sha256HMac);
            }
        }

        /// <summary>
        /// Builder for the TLS 1.1/1.2 key derivation function.
        /// </summary>
        public class TlsKdfWithPrfBuilder
        {
            private readonly FipsAlgorithm algorithm;
            private readonly FipsDigestAlgorithm prf;

            internal TlsKdfWithPrfBuilder(FipsAlgorithm algorithm, FipsDigestAlgorithm prf)
            {
                this.algorithm = algorithm;
                this.prf = prf;
            }

            public TlsKdfWithPrfBuilder WithPrf(FipsDigestAlgorithm prf)
            {
                return new TlsKdfWithPrfBuilder(algorithm, prf);
            }

            public FipsDigestAlgorithm Prf { get { return prf; } }

            public IKdfCalculator<TlsKdfWithPrfParameters> From(byte[] secret, string label, params byte[][] seedMaterial)
            {
                TlsKdfWithPrfParameters parameters = new TlsKdfWithPrfParameters(algorithm, prf, Arrays.Clone(secret), label, Concatenate(seedMaterial));

                return new Tls12KdfFactory(parameters);
            }
        }

        /// <summary>
        /// Parameters for the X9.63 and CONCATENATION key derivation function.
        /// </summary>
        public class AgreementKdfParameters: Parameters<FipsKdfAlgorithm>
		{
			private readonly byte[] shared;
            private readonly byte[] salt;
            private readonly byte[] iv;

            internal AgreementKdfParameters(FipsKdfAlgorithm algorithm, byte[] shared)
                : this(algorithm, shared, null, null)
            {
            }

            internal AgreementKdfParameters(FipsKdfAlgorithm algorithm, byte[] shared, byte[] salt, byte[] iv)
                : base(algorithm)
			{
				this.shared = shared;
                this.salt = salt;
                this.iv = iv;
			}

			public byte[] GetShared() 
			{ 
				return Arrays.Clone(shared); 
			}

			public byte[] GetIV() 
			{ 
				return Arrays.Clone(iv);
			}

            public byte[] GetSalt()
            {
                return Arrays.Clone(salt);
            }

            public FipsPrfAlgorithm Prf { get { return (FipsPrfAlgorithm)Algorithm.Prf; } }
        }

        /// <summary>
        /// TLS protocol stages for KDF usage.
        /// </summary>
		public class TlsStage
		{
			private TlsStage()
			{

			}

			public static readonly String MASTER_SECRET = "master secret";
			public static readonly String KEY_EXPANSION = "key expansion";
            public static readonly String EXTENDED_MASTER_SECRET = "extended master secret";
		}



		private static byte[] Concatenate(params byte[][] seedMaterial)
		{
			int total = seedMaterial [0].Length;
			for (int i = 1; i < seedMaterial.Length; i++) {
				total += seedMaterial [i].Length;
			}

			byte[] rv = new byte[total];

			total = 0;
			for (int i = 0; i < seedMaterial.Length; i++) {
				Array.Copy (seedMaterial [i], 0, rv, total, seedMaterial [i].Length);
				total += seedMaterial [i].Length;
			}

			return rv;
		}

        /// <summary>
        /// Parameters for the TLS 1.0 key derivation function.
        /// </summary>
        public class TlsKdfParameters: Parameters<FipsAlgorithm>
		{
			protected readonly byte[] mSecret;
			protected readonly string mLabel;
			protected readonly byte[] mSeedMaterial;

			internal TlsKdfParameters(FipsAlgorithm algorithm, byte[] secret, string label, byte[] seedMaterial): base(algorithm)
			{
				this.mSecret = secret;
				this.mLabel = label;
				this.mSeedMaterial = seedMaterial;
			}

			public byte[] Secret { get { return Arrays.Clone(mSecret); } }

			public string Label { get { return mLabel; } }

			public byte[] SeedMaterial { get { return Arrays.Clone(mSeedMaterial); } }
		}

        /// <summary>
        /// Parameters for the TLS 1.1/1.2 key derivation function.
        /// </summary>
        public class TlsKdfWithPrfParameters: TlsKdfParameters
		{
			private readonly FipsDigestAlgorithm prf;
		
			internal TlsKdfWithPrfParameters(FipsAlgorithm algorithm, FipsDigestAlgorithm prf, byte[] secret, string label, byte[] seedMaterial): base(algorithm, secret, label, seedMaterial)
			{
				this.prf = prf;
			}
				
			public FipsDigestAlgorithm Prf { get { return prf; } }
		}
			
		private class AgreementKdfCalculator: IKdfCalculator<AgreementKdfParameters>
		{
			private readonly AgreementKdfParameters parameters;
			private readonly IDerivationFunction derivationFunction;

			internal AgreementKdfCalculator(AgreementKdfParameters parameters, IDerivationFunction derivationFunction)
			{
				this.parameters = parameters;
				this.derivationFunction = derivationFunction;
			}

			public AgreementKdfParameters AlgorithmDetails { get { return parameters; } }

			public IBlockResult GetResult(int outputLength)
			{
				byte[] rv = new byte[outputLength];

				derivationFunction.GenerateBytes (rv, 0, rv.Length);

				return new SimpleBlockResult(rv);
			}
		}

		private class HKdfCalculator: IKdfCalculator<AgreementKdfParameters>
		{
			private readonly AgreementKdfParameters parameters;
			private readonly IDerivationFunction derivationFunction;

			internal HKdfCalculator(AgreementKdfParameters parameters, IDerivationFunction derivationFunction)
			{
				this.parameters = parameters;
				this.derivationFunction = derivationFunction;
			}

			public AgreementKdfParameters AlgorithmDetails { get { return parameters; } }

			public IBlockResult GetResult(int outputLength)
			{
				byte[] rv = new byte[outputLength];

				derivationFunction.GenerateBytes (rv, 0, rv.Length);

				return new SimpleBlockResult(rv);
			}
		}

		private class Tls10and11KdfFactory: IKdfCalculator<TlsKdfParameters>
		{
			private readonly TlsKdfParameters parameters;

			internal Tls10and11KdfFactory(TlsKdfParameters parameters)
			{
				this.parameters = parameters;
			}
				
			public TlsKdfParameters AlgorithmDetails { get { return parameters; } }

			public IBlockResult GetResult(int outputLength)
			{
				IMac md5Hmac = new HMac(md5Provider.CreateEngine(EngineUsage.GENERAL));
				IMac sha1HMac = FipsShs.CreateHmac(FipsShs.Sha1HMac);

				return new SimpleBlockResult(PRF_legacy(parameters, outputLength, md5Hmac, sha1HMac));
			}
		}

		private class Tls12KdfFactory: IKdfCalculator<TlsKdfWithPrfParameters>
		{
			private readonly TlsKdfWithPrfParameters parameters;

			internal Tls12KdfFactory(TlsKdfWithPrfParameters parameters)
			{
				this.parameters = parameters;
			}

			public TlsKdfWithPrfParameters AlgorithmDetails { get { return parameters; } }

			public IBlockResult GetResult(int outputLength)
			{
				return new SimpleBlockResult(PRF(parameters, outputLength));
			}
		}

		private static byte[] PRF(TlsKdfWithPrfParameters parameters, int size)
		{
			byte[] label = Strings.ToByteArray(parameters.Label);
			byte[] labelSeed = Arrays.Concatenate(label, parameters.SeedMaterial);

			IMac prfMac = FipsShs.CreateHmac(parameters.Prf);
			byte[] buf = new byte[size];
			HmacHash(prfMac, parameters.Secret, labelSeed, buf);
			return buf;
		}

		private static byte[] PRF_legacy(TlsKdfParameters parameters, int size, IMac md5Hmac, IMac sha1HMac)
		{
			byte[] label = Strings.ToByteArray(parameters.Label);
			byte[] labelSeed = Arrays.Concatenate(label, parameters.SeedMaterial);

			byte[] secret = parameters.Secret;

			int s_half = (secret.Length + 1) / 2;
			byte[] s1 = new byte[s_half];
			byte[] s2 = new byte[s_half];
			Array.Copy(secret, 0, s1, 0, s_half);
			Array.Copy(secret, secret.Length - s_half, s2, 0, s_half);

			byte[] b1 = new byte[size];
			byte[] b2 = new byte[size];
			HmacHash(md5Hmac, s1, labelSeed, b1);
			HmacHash(sha1HMac, s2, labelSeed, b2);
			for (int i = 0; i < size; i++)
			{
				b1[i] ^= b2[i];
			}
			return b1;
		}

		private static void HmacHash(IMac mac, byte[] secret, byte[] seed, byte[] output)
		{
			mac.Init(new KeyParameter(secret));
			byte[] a = seed;
			int size = mac.GetMacSize();
			int iterations = (output.Length + size - 1) / size;
			byte[] buf = new byte[mac.GetMacSize()];
			byte[] buf2 = new byte[mac.GetMacSize()];
			for (int i = 0; i < iterations; i++)
			{
				mac.BlockUpdate(a, 0, a.Length);
				mac.DoFinal(buf, 0);
				a = buf;
				mac.BlockUpdate(a, 0, a.Length);
				mac.BlockUpdate(seed, 0, seed.Length);
				mac.DoFinal(buf2, 0);
				Array.Copy(buf2, 0, output, (size * i), System.Math.Min(size, output.Length - (size * i)));
			}
		}

        private class MD5Provider: IEngineProvider<IDigest>
		{
			public IDigest CreateEngine(EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Tls1_0.Algorithm, new MD5Digest (), new Md5KatTest());
			}
		}

        private class Md5KatTest: IBasicKatTest<IDigest>
        {
            private static readonly byte[] stdShaVector = Strings.ToByteArray("abc");

            public bool HasTestPassed(IDigest digest)
            {
                digest.BlockUpdate(stdShaVector, 0, stdShaVector.Length);

                byte[] result = new byte[digest.GetDigestSize()];

                digest.DoFinal(result, 0);

                return Arrays.AreEqual(FipsKats.Values[FipsKats.Vec.MD5], result);
            }
        }

        private class ConcatenationKdfProvider : IEngineProvider<IDerivationFunction>
        {
            private readonly FipsDigestAlgorithm prf;

            internal ConcatenationKdfProvider(FipsPrfAlgorithm prfAlg)
            {
                this.prf = (FipsDigestAlgorithm)prfAlg.BaseAlgorithm;
            }

            public IDerivationFunction CreateEngine(EngineUsage usage)
            {
                IDigest digest = FipsShs.CreateDigest(prf);
                IDerivationFunction df;

                if (digest != null)
                {
                    df = new ConcatenationKdfGenerator(digest);
                }
                else
                {
                    IMac mac = FipsShs.CreateHmac(prf);
                    if (mac == null)
                    {
                        if (prf.Equals(FipsShs.Algorithm.KMAC128))
                        {
                            mac = new KMac(128, 256,  Strings.ToByteArray("KDF"));   // see section 4, SP 800-56C
                        }
                        else if (prf.Equals(FipsShs.Algorithm.KMAC256))
                        {
                            mac = new KMac(256, 512, Strings.ToByteArray("KDF"));
                        }
                        else
                        {
                            throw new ArgumentException("PRF not recognized");
                        }
                    }
                    df = new ConcatenationKdfGenerator(mac);
                }

                return SelfTestExecutor.Validate(prf, df, new ConcatenationKatTest(prf));
            }
        }

        private class ConcatenationKatTest : IBasicKatTest<IDerivationFunction>
        {
            private static readonly byte[] KI = Hex.DecodeStrict("dff1e50ac0b69dc40f1051d46c2b069c");
            private static readonly byte[] SALT = Hex.DecodeStrict("000102030405060708090a0b0c0d0e0f");
            private static readonly byte[] IV = Hex.DecodeStrict("0f0e0d0c0b0a09080706050403020100");

            private static readonly IDictionary expected = Platform.CreateHashtable();

            static ConcatenationKatTest()
            {
                expected.Add(FipsShs.Algorithm.SHA1, FipsKats.Vec.CKdfSha1_vec);
                expected.Add(FipsShs.Algorithm.SHA224, FipsKats.Vec.CKdfSha224_vec);
                expected.Add(FipsShs.Algorithm.SHA256, FipsKats.Vec.CKdfSha256_vec);
                expected.Add(FipsShs.Algorithm.SHA384, FipsKats.Vec.CKdfSha384_vec);
                expected.Add(FipsShs.Algorithm.SHA512, FipsKats.Vec.CKdfSha512_vec);
                expected.Add(FipsShs.Algorithm.SHA512_224, FipsKats.Vec.CKdfSha512_224_vec);
                expected.Add(FipsShs.Algorithm.SHA512_256, FipsKats.Vec.CKdfSha512_256_vec);
                expected.Add(FipsShs.Algorithm.SHA3_224, FipsKats.Vec.CKdfSha3_224_vec);
                expected.Add(FipsShs.Algorithm.SHA3_256, FipsKats.Vec.CKdfSha3_256_vec);
                expected.Add(FipsShs.Algorithm.SHA3_384, FipsKats.Vec.CKdfSha3_384_vec);
                expected.Add(FipsShs.Algorithm.SHA3_512, FipsKats.Vec.CKdfSha3_512_vec);
                expected.Add(FipsShs.Algorithm.SHA1_HMAC, FipsKats.Vec.CKdfSha1hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA224_HMAC, FipsKats.Vec.CKdfSha224hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA256_HMAC, FipsKats.Vec.CKdfSha256hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA384_HMAC, FipsKats.Vec.CKdfSha384hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA512_HMAC, FipsKats.Vec.CKdfSha512hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA512_224_HMAC, FipsKats.Vec.CKdfSha512_224hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA512_256_HMAC, FipsKats.Vec.CKdfSha512_256hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA3_224_HMAC, FipsKats.Vec.CKdfSha3_224hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA3_256_HMAC, FipsKats.Vec.CKdfSha3_256hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA3_384_HMAC, FipsKats.Vec.CKdfSha3_384hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA3_512_HMAC, FipsKats.Vec.CKdfSha3_512hmac_vec);
                expected.Add(FipsShs.Algorithm.KMAC128, FipsKats.Vec.CKdfKMac128_vec);
                expected.Add(FipsShs.Algorithm.KMAC256, FipsKats.Vec.CKdfKMac256_vec);
            }

            private readonly FipsDigestAlgorithm prf;

            internal ConcatenationKatTest(FipsDigestAlgorithm prf)
            {
                this.prf = prf;
            }

            public bool HasTestPassed(IDerivationFunction df)
            {
                df.Init(new KdfParameters(KI, SALT, IV));

                byte[] output = new byte[10];

                df.GenerateBytes(output, 0, output.Length);

                return Arrays.AreEqual(ExpectedOutput(prf), output);
            }

            private static byte[] ExpectedOutput(FipsDigestAlgorithm prf)
            {
                return FipsKats.Values[(FipsKats.Vec)expected[prf]];
            }
        }

        private class X963KdfProvider : IEngineProvider<IDerivationFunction>
        {
            private readonly FipsDigestAlgorithm prf;

            internal X963KdfProvider(FipsPrfAlgorithm prfAlg)
            {
                this.prf = (FipsDigestAlgorithm)prfAlg.BaseAlgorithm;
            }

            public IDerivationFunction CreateEngine(EngineUsage usage)
            {
                IDerivationFunction df = new Kdf2BytesGenerator(FipsShs.CreateDigest((FipsDigestAlgorithm)prf));

                return SelfTestExecutor.Validate(prf, df, new X963KatTest(prf));
            }
        }

        private class X963KatTest : IBasicKatTest<IDerivationFunction>
        {
            private static readonly byte[] KI = Hex.Decode("dff1e50ac0b69dc40f1051d46c2b069c");
            private static readonly byte[] IV = Hex.DecodeStrict("0f0e0d0c0b0a09080706050403020100");

            private static readonly IDictionary expected = Platform.CreateHashtable();

            static X963KatTest()
            {
                expected.Add(FipsShs.Algorithm.SHA1, FipsKats.Vec.X963Sha1_vec);
                expected.Add(FipsShs.Algorithm.SHA224, FipsKats.Vec.X963Sha224_vec);
                expected.Add(FipsShs.Algorithm.SHA256, FipsKats.Vec.X963Sha256_vec);
                expected.Add(FipsShs.Algorithm.SHA384, FipsKats.Vec.X963Sha384_vec);
                expected.Add(FipsShs.Algorithm.SHA512, FipsKats.Vec.X963Sha512_vec);
                expected.Add(FipsShs.Algorithm.SHA512_224, FipsKats.Vec.X963Sha512_224_vec);
                expected.Add(FipsShs.Algorithm.SHA512_256, FipsKats.Vec.X963Sha512_256_vec);
                expected.Add(FipsShs.Algorithm.SHA3_224, FipsKats.Vec.X963Sha3_224_vec);
                expected.Add(FipsShs.Algorithm.SHA3_256, FipsKats.Vec.X963Sha3_256_vec);
                expected.Add(FipsShs.Algorithm.SHA3_384, FipsKats.Vec.X963Sha3_384_vec);
                expected.Add(FipsShs.Algorithm.SHA3_512, FipsKats.Vec.X963Sha3_512_vec);
            }

            private readonly FipsDigestAlgorithm prf;

            internal X963KatTest(FipsDigestAlgorithm prf)
            {
                this.prf = prf;
            }

            public bool HasTestPassed(IDerivationFunction df)
            {
                df.Init(new KdfParameters(KI, IV));

                byte[] output = new byte[10];

                df.GenerateBytes(output, 0, output.Length);

                return Arrays.AreEqual(ExpectedOutput(prf), output);
            }

            private static byte[] ExpectedOutput(FipsDigestAlgorithm prf)
            {
                return FipsKats.Values[(FipsKats.Vec)expected[prf]];
            }
        }

        private class HKdfProvider : IEngineProvider<IDerivationFunction>
        {
            private readonly FipsDigestAlgorithm prf;

            internal HKdfProvider(FipsPrfAlgorithm prfAlg)
            {
                this.prf = (FipsDigestAlgorithm)prfAlg.BaseAlgorithm;
            }

            public IDerivationFunction CreateEngine(EngineUsage usage)
            {
                IMac mac = FipsShs.CreateHmac((FipsDigestAlgorithm)prf);
                IDerivationFunction df = new HKdfBytesGenerator(mac);

                return SelfTestExecutor.Validate(prf, df, new HKdfKatTest(prf));
            }
        }

        private class HKdfKatTest : IBasicKatTest<IDerivationFunction>
        {
            private static readonly byte[] KI = Hex.Decode("dff1e50ac0b69dc40f1051d46c2b069c");
            private static readonly byte[] IV = Hex.DecodeStrict("0f0e0d0c0b0a09080706050403020100");

            private static readonly IDictionary expected = Platform.CreateHashtable();

            static HKdfKatTest()
            {
                expected.Add(FipsShs.Algorithm.SHA1_HMAC, FipsKats.Vec.HKdfSha1hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA224_HMAC, FipsKats.Vec.HKdfSha224hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA256_HMAC, FipsKats.Vec.HKdfSha256hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA384_HMAC, FipsKats.Vec.HKdfSha384hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA512_HMAC, FipsKats.Vec.HKdfSha512hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA512_224_HMAC, FipsKats.Vec.HKdfSha512_224hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA512_256_HMAC, FipsKats.Vec.HKdfSha512_256hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA3_224_HMAC, FipsKats.Vec.HKdfSha3_224hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA3_256_HMAC, FipsKats.Vec.HKdfSha3_256hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA3_384_HMAC, FipsKats.Vec.HKdfSha3_384hmac_vec);
                expected.Add(FipsShs.Algorithm.SHA3_512_HMAC, FipsKats.Vec.HKdfSha3_512hmac_vec);
            }

            private readonly FipsDigestAlgorithm prf;

            internal HKdfKatTest(FipsDigestAlgorithm prf)
            {
                this.prf = prf;
            }

            public bool HasTestPassed(IDerivationFunction df)
            {
                df.Init(new HKdfParameters(new KeyParameter(KI), IV));

                byte[] output = new byte[10];

                df.GenerateBytes(output, 0, output.Length);

                return Arrays.AreEqual(ExpectedOutput(prf), output);
            }

            private static byte[] ExpectedOutput(FipsDigestAlgorithm prf)
            {
                return FipsKats.Values[(FipsKats.Vec)expected[prf]];
            }
        }

        private static void TlsLegacyKat()
        {
            IMac md5Hmac = new HMac(md5Provider.CreateEngine(EngineUsage.GENERAL));
            IMac sha1HMac = FipsShs.CreateHmac(FipsShs.Algorithm.SHA1_HMAC);

            TlsKdfParameters testParams = new TlsKdfParameters(Tls1_0.Algorithm, Hex.Decode("0102030405060708090a0b0c0d0e0f"), TlsStage.MASTER_SECRET, Hex.Decode("deadbeefbeefdead"));
            byte[] kat = PRF_legacy(testParams, 32, md5Hmac, sha1HMac);
            if (!Arrays.AreEqual(kat, FipsKats.Values[FipsKats.Vec.TlsLegacyKat]))
            {
                CryptoStatus.MoveToErrorStatus(new SelfTestFailedError("Exception on self test: TLS Legacy KAT", Tls1_0.Algorithm));
            }
        }

        private static void Tls1_1and2Kat()
        {
            TlsKdfWithPrfParameters testParams = new TlsKdfWithPrfParameters(Tls1_2.Algorithm, FipsShs.Sha256HMac, Hex.Decode("0102030405060708090a0b0c0d0e0f"), TlsStage.MASTER_SECRET, Hex.Decode("deadbeefbeefdead"));
            byte[] kat = PRF(testParams, 32);
            if (!Arrays.AreEqual(kat, FipsKats.Values[FipsKats.Vec.Tls1_1and1_2Kat]))
            {
                CryptoStatus.MoveToErrorStatus(new SelfTestFailedError("Exception on self test: TLS KAT", Tls1_1.Algorithm));
            }
        }
    }
}

