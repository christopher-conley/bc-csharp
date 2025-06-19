using System;
using System.Collections;

using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Internal.Digests;
using Org.BouncyCastle.Crypto.Internal.Macs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Fips
{
    /// <summary>
    /// Source class for implementations of FIPS approved secure hash algorithms.
    /// </summary>
	public class FipsShs
	{
		internal static class Algorithm 
		{
			internal static readonly FipsDigestAlgorithm SHA1 = new FipsDigestAlgorithm("SHA-1");
			internal static readonly FipsDigestAlgorithm SHA1_HMAC = new FipsDigestAlgorithm("SHA-1", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA224 = new FipsDigestAlgorithm("SHA-224");
			internal static readonly FipsDigestAlgorithm SHA224_HMAC = new FipsDigestAlgorithm("SHA-224", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA256 = new FipsDigestAlgorithm("SHA-256");
			internal static readonly FipsDigestAlgorithm SHA256_HMAC = new FipsDigestAlgorithm("SHA-256", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA384 = new FipsDigestAlgorithm("SHA-384");
			internal static readonly FipsDigestAlgorithm SHA384_HMAC = new FipsDigestAlgorithm("SHA-384", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA512 = new FipsDigestAlgorithm("SHA-512");
			internal static readonly FipsDigestAlgorithm SHA512_HMAC = new FipsDigestAlgorithm("SHA-512", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA512_224 = new FipsDigestAlgorithm("SHA-512(224)");
			internal static readonly FipsDigestAlgorithm SHA512_224_HMAC = new FipsDigestAlgorithm("SHA-512(224)", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA512_256 = new FipsDigestAlgorithm("SHA-512(256)");
			internal static readonly FipsDigestAlgorithm SHA512_256_HMAC = new FipsDigestAlgorithm("SHA-512(256)", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA3_224 = new FipsDigestAlgorithm("SHA3-224");
			internal static readonly FipsDigestAlgorithm SHA3_256 = new FipsDigestAlgorithm("SHA3-256");
			internal static readonly FipsDigestAlgorithm SHA3_384 = new FipsDigestAlgorithm("SHA3-384");
			internal static readonly FipsDigestAlgorithm SHA3_512 = new FipsDigestAlgorithm("SHA3-512");
			internal static readonly FipsDigestAlgorithm SHA3_224_HMAC = new FipsDigestAlgorithm("SHA3-224/HMAC", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA3_256_HMAC = new FipsDigestAlgorithm("SHA3-256/HMAC", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA3_384_HMAC = new FipsDigestAlgorithm("SHA3-384/HMAC", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHA3_512_HMAC = new FipsDigestAlgorithm("SHA3-512/HMAC", AlgorithmMode.HMAC);
			internal static readonly FipsDigestAlgorithm SHAKE128 = new FipsDigestAlgorithm("SHAKE128");
			internal static readonly FipsDigestAlgorithm SHAKE256 = new FipsDigestAlgorithm("SHAKE256");
			internal static readonly FipsDigestAlgorithm CSHAKE128 = new FipsDigestAlgorithm("cSHAKE128");
			internal static readonly FipsDigestAlgorithm CSHAKE256 = new FipsDigestAlgorithm("cSHAKE256");

			internal static readonly FipsDigestAlgorithm KMAC128 = new FipsDigestAlgorithm("KMAC128");
			internal static readonly FipsDigestAlgorithm KMAC256 = new FipsDigestAlgorithm("KMAC256");

			internal static readonly FipsDigestAlgorithm TupleHash128 = new FipsDigestAlgorithm("TupleHash128");
			internal static readonly FipsDigestAlgorithm TupleHash256 = new FipsDigestAlgorithm("TupleHash256");

			internal static readonly FipsDigestAlgorithm ParallelHash128 = new FipsDigestAlgorithm("ParallelHash128");
			internal static readonly FipsDigestAlgorithm ParallelHash256 = new FipsDigestAlgorithm("ParallelHash256");
		}

        /// <summary>
        /// The SHA-1 Digest marker.
        /// </summary>
		public static readonly Parameters Sha1 = new Parameters(Algorithm.SHA1);

        /// <summary>
        /// The SHA-224 Digest marker.
        /// </summary>
        public static readonly Parameters Sha224 = new Parameters(Algorithm.SHA224);

        /// <summary>
        /// The SHA-256 Digest marker.
        /// </summary>
        public static readonly Parameters Sha256 = new Parameters(Algorithm.SHA256);

        /// <summary>
        /// The SHA-384 Digest marker.
        /// </summary>
        public static readonly Parameters Sha384 = new Parameters(Algorithm.SHA384);

        /// <summary>
        /// The SHA-512 Digest marker.
        /// </summary>
        public static readonly Parameters Sha512 = new Parameters(Algorithm.SHA512);

        /// <summary>
        /// The SHA512(224) Digest marker.
        /// </summary>
        public static readonly Parameters Sha512_224 = new Parameters(Algorithm.SHA512_224);

        /// <summary>
        /// The SHA512(256) Digest marker.
        /// </summary>
        public static readonly Parameters Sha512_256 = new Parameters(Algorithm.SHA512_256);

        /// <summary>
        /// The SHA3-224 Digest marker.
        /// </summary>
        public static readonly Parameters Sha3_224 = new Parameters(Algorithm.SHA3_224);

        /// <summary>
        /// The SHA3-256 Digest marker.
        /// </summary>
        public static readonly Parameters Sha3_256 = new Parameters(Algorithm.SHA3_256);

        /// <summary>
        /// The SHA3-384 Digest marker.
        /// </summary>
        public static readonly Parameters Sha3_384 = new Parameters(Algorithm.SHA3_384);

        /// <summary>
        /// The SHA3-512 Digest marker.
        /// </summary>
        public static readonly Parameters Sha3_512 = new Parameters(Algorithm.SHA3_512);

        /// <summary>
        /// The SHA-1 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha1HMac = new AuthenticationParameters(Algorithm.SHA1_HMAC, 160);

        /// <summary>
        /// The SHA-224 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha224HMac = new AuthenticationParameters(Algorithm.SHA224_HMAC, 224);

        /// <summary>
        /// The SHA-256 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha256HMac = new AuthenticationParameters(Algorithm.SHA256_HMAC, 256);

        /// <summary>
        /// The SHA-384 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha384HMac = new AuthenticationParameters(Algorithm.SHA384_HMAC, 384);
       
        /// <summary>
        /// The SHA-512 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha512HMac = new AuthenticationParameters(Algorithm.SHA512_HMAC, 512);

        /// <summary>
        /// The SHA-512(224) HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha512_224HMac = new AuthenticationParameters(Algorithm.SHA512_224_HMAC, 224);

        /// <summary>
        /// The SHA-512(256) HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha512_256HMac = new AuthenticationParameters(Algorithm.SHA512_256_HMAC, 256);

        /// <summary>
        /// The SHA3-224 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha3_224HMac = new AuthenticationParameters(Algorithm.SHA3_224_HMAC, 224);

        /// <summary>
        /// The SHA3-256 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha3_256HMac = new AuthenticationParameters(Algorithm.SHA3_256_HMAC, 256);

        /// <summary>
        /// The SHA3-384 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha3_384HMac = new AuthenticationParameters(Algorithm.SHA3_384_HMAC, 384);
       
        /// <summary>
        /// The SHA3-512 HMAC parameters source.
        /// </summary>
        public static readonly AuthenticationParameters Sha3_512HMac = new AuthenticationParameters(Algorithm.SHA3_512_HMAC, 512);

        /// <summary>
        /// The SHAKE128 parameters source.
        /// </summary>
		public static readonly XofParameters Shake128 = new XofParameters(Algorithm.SHAKE128);

        /// <summary>
        /// The SHAKE256 parameters source.
        /// </summary>
		public static readonly XofParameters Shake256 = new XofParameters(Algorithm.SHAKE256);

        /// <summary>
        /// The cSHAKE128 parameters source.
        /// </summary>
		public static readonly CShakeParameters CShake128 = new CShakeParameters(Algorithm.CSHAKE128, null, null, 256);

        /// <summary>
        /// The cSHAKE256 parameters source.
        /// </summary>
		public static readonly CShakeParameters CShake256 = new CShakeParameters(Algorithm.CSHAKE256, null, null, 512);
		
		/// <summary>
        /// The KMac128 parameters source.
        /// </summary>
		public static readonly KMacParameters KMac128 = new KMacParameters(Algorithm.KMAC128, null, 256);

        /// <summary>
        /// The KMac256 parameters source.
        /// </summary>
		public static readonly KMacParameters KMac256 = new KMacParameters(Algorithm.KMAC256, null, 512);

		/// <summary>
        /// TheTupleHash128 parameters source.
        /// </summary>
		public static readonly TupleHashParameters TupleHash128 = new TupleHashParameters(Algorithm.TupleHash128, null, 256);

        /// <summary>
        /// The TupleHash256 parameters source.
        /// </summary>
		public static readonly TupleHashParameters TupleHash256 = new TupleHashParameters(Algorithm.TupleHash256, null, 512);
		
		/// <summary>
        /// The ParallelHash128 parameters source.
        /// </summary>
		public static readonly ParallelHashParameters ParallelHash128 = new ParallelHashParameters(Algorithm.ParallelHash128, null, 32, 256);

        /// <summary>
        /// The ParallelHash256 parameters source.
        /// </summary>
		public static readonly ParallelHashParameters ParallelHash256 = new ParallelHashParameters(Algorithm.ParallelHash256, null, 64, 512);

        private static readonly IDictionary digestProviders = Platform.CreateHashtable();
        private static readonly IDictionary xofProviders = Platform.CreateHashtable();
        private static readonly IDictionary hmacProviders = Platform.CreateHashtable();

        static FipsShs()
        {
            digestProviders[Sha1] = digestProviders[Sha1.Algorithm] = new Sha1DigestProvider();
            digestProviders[Sha224] = digestProviders[Sha224.Algorithm] = new Sha224DigestProvider();
            digestProviders[Sha256] = digestProviders[Sha256.Algorithm] = new Sha256DigestProvider();
            digestProviders[Sha384] = digestProviders[Sha384.Algorithm] = new Sha384DigestProvider();
            digestProviders[Sha512] = digestProviders[Sha512.Algorithm] = new Sha512DigestProvider();
            digestProviders[Sha512_224] = digestProviders[Sha512_224.Algorithm] = new Sha512_224DigestProvider();
            digestProviders[Sha512_256] = digestProviders[Sha512_256.Algorithm] = new Sha512_256DigestProvider();
            digestProviders[Sha3_224] = digestProviders[Sha3_224.Algorithm] = new Sha3_224DigestProvider();
            digestProviders[Sha3_256] = digestProviders[Sha3_256.Algorithm] = new Sha3_256DigestProvider();
            digestProviders[Sha3_384] = digestProviders[Sha3_384.Algorithm] = new Sha3_384DigestProvider();
            digestProviders[Sha3_512] = digestProviders[Sha3_512.Algorithm] = new Sha3_512DigestProvider();
            digestProviders[Shake128] = digestProviders[Shake128.Algorithm] = new Shake128DigestProvider();
            digestProviders[Shake256] = digestProviders[Shake256.Algorithm] = new Shake256DigestProvider();

            xofProviders[Shake128.Algorithm] = new Shake128Provider();
            xofProviders[Shake256.Algorithm] = new Shake256Provider();
            xofProviders[CShake128.Algorithm] = new CShake128Provider();
            xofProviders[CShake256.Algorithm] = new CShake256Provider();
			xofProviders[KMac128.Algorithm] = new KMac128Provider();
            xofProviders[KMac256.Algorithm] = new KMac256Provider();
			xofProviders[TupleHash128.Algorithm] = new TupleHash128Provider();
            xofProviders[TupleHash256.Algorithm] = new TupleHash256Provider();
			xofProviders[ParallelHash128.Algorithm] = new ParallelHash128Provider();
            xofProviders[ParallelHash256.Algorithm] = new ParallelHash256Provider();
        
            hmacProviders[Sha1.Algorithm] = new Sha1HmacProvider();
            hmacProviders[Sha224.Algorithm] = new Sha224HmacProvider();
            hmacProviders[Sha256.Algorithm] = new Sha256HmacProvider();
            hmacProviders[Sha384.Algorithm] = new Sha384HmacProvider();
            hmacProviders[Sha512.Algorithm] = new Sha512HmacProvider();
            hmacProviders[Sha512_224.Algorithm] = new Sha512_224HmacProvider();
            hmacProviders[Sha512_256.Algorithm] = new Sha512_256HmacProvider();
            hmacProviders[Sha1HMac.Algorithm] = new Sha1HmacProvider();
            hmacProviders[Sha224HMac.Algorithm] = new Sha224HmacProvider();
            hmacProviders[Sha256HMac.Algorithm] = new Sha256HmacProvider();
            hmacProviders[Sha384HMac.Algorithm] = new Sha384HmacProvider();
            hmacProviders[Sha512HMac.Algorithm] = new Sha512HmacProvider();
            hmacProviders[Sha512_224HMac.Algorithm] = new Sha512_224HmacProvider();
            hmacProviders[Sha512_256HMac.Algorithm] = new Sha512_256HmacProvider();
            hmacProviders[Sha3_224HMac.Algorithm] = new Sha3_224HmacProvider();
            hmacProviders[Sha3_256HMac.Algorithm] = new Sha3_256HmacProvider();
            hmacProviders[Sha3_384HMac.Algorithm] = new Sha3_384HmacProvider();
            hmacProviders[Sha3_512HMac.Algorithm] = new Sha3_512HmacProvider();

            // FSM_STATE:3.SHS.0,"SECURE HASH GENERATE VERIFY KAT", "The module is performing Secure Hash generate and verify KAT self-tests"
            // FSM_TRANS:3.SHS.0, "POWER ON SELF-TEST",	"SECURE HASH GENERATE VERIFY KAT",	"Invoke Secure Hash Generate/Verify KAT self-test"
            for (IEnumerator en = digestProviders.Keys.GetEnumerator(); en.MoveNext();)
            {
                ((DigestEngineProvider)digestProviders[en.Current]).CreateEngine(EngineUsage.GENERAL);
            }
            // FSM_TRANS:3.SHS.1, "SECURE HASH GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"Secure Hash Generate/Verify KAT self-test successful completion"

            // FSM_STATE:3.SHS.1,"HMAC GENERATE VERIFY KAT", "The module is performing HMAC generate and verify KAT self-tests"
            // FSM_TRANS:3.SHS.2,"POWER ON SELF-TEST", "HMAC GENERATE VERIFY KAT", "Invoke HMAC Generate/Verify KAT self-test"
            for (IEnumerator en = hmacProviders.Keys.GetEnumerator(); en.MoveNext();)
            {
                ((HmacEngineProvider)hmacProviders[en.Current]).CreateEngine(EngineUsage.GENERAL);
            }
            // FSM_TRANS:3.SHS.3, "HMAC GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"HMAC Generate/Verify KAT self-test successful completion"

            // FSM_STATE:3.SHS.2,"XOF GENERATE VERIFY KAT", "The module is performing Extendable Output Function generate and verify KAT self-tests"
            // FSM_TRANS:3.SHS.3,"POWER ON SELF-TEST", "XOF GENERATE VERIFY KAT", "Invoke XOF Generate/Verify KAT self-test"
            ((XofEngineProvider<XofParameters>)xofProviders[Shake256.Algorithm]).CreateEngine(EngineUsage.GENERAL, Shake256);
            ((XofEngineProvider<CShakeParameters>)xofProviders[CShake128.Algorithm]).CreateEngine(EngineUsage.GENERAL, CShake128);
            // FSM_TRANS:3.SHS.4, "XOF GENERATE VERIFY KAT", "POWER ON SELF-TEST",	"XOF Generate/Verify KAT self-test successful completion"
        }

        private FipsShs()
        {
        }

        /// <summary>
        /// Generic digest parameters.
        /// </summary>
        public class Parameters: FipsDigestAlgorithm, IParameters<FipsDigestAlgorithm>, IFactoryServiceType<IDigestFactory<Parameters>>, IFactoryService<IDigestFactory<Parameters>>
        {
			internal Parameters(FipsDigestAlgorithm algorithm): base(algorithm.Name, algorithm.Mode)
			{
			}

			public FipsDigestAlgorithm Algorithm {
				get { return this; }
			}

            Func<IParameters<Crypto.Algorithm>, IDigestFactory<Parameters>> IFactoryService<IDigestFactory<Parameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new Provider().CreateDigestFactory(parameters as Parameters);
            }
        }

        /// <summary>
        /// Generic eXpandable output function (XOF) parameters.
        /// </summary>
		public class XofParameters: FipsDigestAlgorithm, IParameters<FipsDigestAlgorithm>, IFactoryServiceType<IXofFactory<XofParameters>>, IFactoryService<IXofFactory<XofParameters>>
        {
			internal XofParameters(FipsDigestAlgorithm algorithm): base(algorithm.Name)
			{
			}

			public FipsDigestAlgorithm Algorithm {
				get { return this; }
			}

            Func<IParameters<Crypto.Algorithm>, IXofFactory<XofParameters>> IFactoryService<IXofFactory<XofParameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new Provider().CreateXofFactory(parameters as XofParameters);
            }
        }

        /// <summary>
        /// Generic Customizable eXpandable output function (XOF) parameters.
        /// </summary>
        public class CXofParameters : FipsDigestAlgorithm, IParameters<FipsDigestAlgorithm>
        {
            internal readonly byte[] customizationString;
            internal readonly int defaultOutputSizeInBits;

            internal CXofParameters(FipsDigestAlgorithm algorithm, byte[] customizationString, int defaultOutputSizeInBits) : base(algorithm.Name)
            {
                this.customizationString = customizationString;
                this.defaultOutputSizeInBits = defaultOutputSizeInBits;
            }

            public FipsDigestAlgorithm Algorithm
            {
                get { return this; }
            }

            public byte[] GetCustomizationString()
            {
                return Arrays.Clone(customizationString);
            }
        }

        public class CShakeParameters : CXofParameters, IFactoryServiceType<IXofFactory<CShakeParameters>>, IFactoryService<IXofFactory<CShakeParameters>>
        {
            internal byte[] functionString;

            internal CShakeParameters(FipsDigestAlgorithm algorithm, byte[] functionString, byte[] customizationString, int defaultOutputSizeInBits) : base(algorithm, customizationString, defaultOutputSizeInBits)
            {
                this.functionString = functionString;
            }

            public int DefaultOutputSizeInBits
            {
                get { return defaultOutputSizeInBits; }
            }

            public byte[] GetFunctionName()
            {
                return Arrays.Clone(functionString);
            }

            public CShakeParameters WithDefaultSize(int defaultSizeInBits)
            {
                return new CShakeParameters(this.Algorithm, functionString, customizationString, defaultSizeInBits);
            }

            public CShakeParameters WithFunctionName(byte[] functionName)
            {
                return new CShakeParameters(this.Algorithm, Arrays.Clone(functionName), customizationString, defaultOutputSizeInBits);
            }

            public CShakeParameters WithCustomizationString(byte[] customizationString)
            {
                return new CShakeParameters(this.Algorithm, functionString, Arrays.Clone(customizationString), defaultOutputSizeInBits);
            }

            Func<IParameters<Crypto.Algorithm>, IXofFactory<CShakeParameters>> IFactoryService<IXofFactory<CShakeParameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new Provider().CreateXofFactory(parameters as CShakeParameters);
            }
        }

        public class KMacParameters : CXofParameters, IAuthenticationParameters<KMacParameters, FipsDigestAlgorithm>, IFactoryServiceType<IXofFactory<KMacParameters>>, IFactoryService<IXofFactory<KMacParameters>>
        {
            internal KMacParameters(FipsDigestAlgorithm algorithm, byte[] customizationString, int defaultOutputSizeInBits) : base(algorithm, customizationString, defaultOutputSizeInBits)
            {
            }

            public int MacSizeInBits
            {
                get { return defaultOutputSizeInBits; }
            }

            public KMacParameters WithCustomizationString(byte[] customizationString)
            {
                return new KMacParameters(this.Algorithm, Arrays.Clone(customizationString), defaultOutputSizeInBits);
            }

            public KMacParameters WithMacSize(int macSizeInBits)
            {
                return new KMacParameters(this.Algorithm, customizationString, macSizeInBits);
            }

            Func<IParameters<Crypto.Algorithm>, IXofFactory<KMacParameters>> IFactoryService<IXofFactory<KMacParameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new Provider().CreateXofFactory(parameters as KMacParameters);
            }
        }

        public class ParallelHashParameters : CXofParameters, IFactoryServiceType<IXofFactory<ParallelHashParameters>>, IFactoryService<IXofFactory<ParallelHashParameters>>
        {
            internal readonly int blockSize;

            internal ParallelHashParameters(FipsDigestAlgorithm algorithm, byte[] customizationString, int blockSize, int defaultOutputSizeInBits) : base(algorithm, customizationString, defaultOutputSizeInBits)
            {
                this.blockSize = blockSize;
            }

            public int DigestSizeInBits
            {
                get { return defaultOutputSizeInBits; }
            }

            public ParallelHashParameters WithDigestSize(int sizeInBits)
            {
                return new ParallelHashParameters(this.Algorithm, customizationString, blockSize, sizeInBits);
            }

            public ParallelHashParameters WithCustomizationString(byte[] customizationString)
            {
                return new ParallelHashParameters(this.Algorithm, Arrays.Clone(customizationString), blockSize, defaultOutputSizeInBits);
            }

            public ParallelHashParameters WithBlockLength(int blockLength)
            {
                return new ParallelHashParameters(this.Algorithm, customizationString, blockLength, defaultOutputSizeInBits);
            }

            Func<IParameters<Crypto.Algorithm>, IXofFactory<ParallelHashParameters>> IFactoryService<IXofFactory<ParallelHashParameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new Provider().CreateXofFactory(parameters as ParallelHashParameters);
            }
        }

        public class TupleHashParameters: CXofParameters, IFactoryServiceType<IXofFactory<TupleHashParameters>>, IFactoryService<IXofFactory<TupleHashParameters>>
        {
            internal TupleHashParameters(FipsDigestAlgorithm algorithm, byte[] customizationString, int defaultOutputSizeInBits) : base(algorithm, customizationString, defaultOutputSizeInBits)
            {
            }

            public int DigestSizeInBits
            {
                get { return defaultOutputSizeInBits; }
            }

            public TupleHashParameters WithDigestSize(int sizeInBits)
            {
                return new TupleHashParameters(this.Algorithm, customizationString, sizeInBits);
            }

            public TupleHashParameters WithCustomizationString(byte[] customizationString)
            {
                return new TupleHashParameters(this.Algorithm, Arrays.Clone(customizationString), defaultOutputSizeInBits);
            }

            Func<IParameters<Crypto.Algorithm>, IXofFactory<TupleHashParameters>> IFactoryService<IXofFactory<TupleHashParameters>>.GetFunc(SecurityContext context)
            {
                return (parameters) => new Provider().CreateXofFactory(parameters as TupleHashParameters);
            }
        }

        /// <summary>
        /// Parameters for HMAC modes.
        /// </summary>
		public class AuthenticationParameters: FipsDigestAlgorithm, IAuthenticationParameters<AuthenticationParameters, FipsDigestAlgorithm>
		{
			private readonly FipsDigestAlgorithm algorithm;
			private readonly int macSizeInBits;

			internal AuthenticationParameters (FipsDigestAlgorithm algorithm, int macSizeInBits):base(algorithm.Name, algorithm.Mode)
			{
				this.algorithm = algorithm;
				this.macSizeInBits = macSizeInBits;
			}

			public FipsDigestAlgorithm Algorithm {
				get { return this.algorithm; }
			}

			/// <summary>
			/// Return the size of the MAC these parameters are for.
			/// </summary>
			/// <value>The MAC size in bits.</value>
			public int MacSizeInBits { get { return macSizeInBits; } }

			/// <summary>
			/// Create a new parameter set with the specified MAC size associated with it.
			/// </summary>
			/// <returns>The new parameter set.</returns>
			/// <param name="macSizeInBits">Mac size in bits.</param>
			public AuthenticationParameters WithMacSize(int macSizeInBits)
			{
				return new AuthenticationParameters (this.algorithm, macSizeInBits);
			}
		}

		private class Provider: IDigestFactoryProvider<Parameters>, IXofFactoryProvider<XofParameters>,
            IXofFactoryProvider<CShakeParameters>, IXofFactoryProvider<KMacParameters>, IXofFactoryProvider<ParallelHashParameters>, IXofFactoryProvider<TupleHashParameters>  
		{
			public IDigestFactory<Parameters> CreateDigestFactory (Parameters algorithmDetails)
			{
				DigestEngineProvider digestProvider = (DigestEngineProvider)digestProviders[algorithmDetails.Algorithm];

				return new DigestFactory<Parameters>(algorithmDetails, digestProvider, digestProvider.DigestSize);
			}

            public IXofFactory<XofParameters> CreateXofFactory(XofParameters algorithmDetails)
            {
                XofEngineProvider<XofParameters> xofProvider = (XofEngineProvider<XofParameters>)xofProviders[algorithmDetails.Algorithm];

                return new XofFactory<XofParameters>(algorithmDetails, xofProvider);
            }

            public IXofFactory<CShakeParameters> CreateXofFactory(CShakeParameters algorithmDetails)
            {
                XofEngineProvider<CShakeParameters> xofProvider = (XofEngineProvider<CShakeParameters>)xofProviders[algorithmDetails.Algorithm];

                return new XofFactory<CShakeParameters>(algorithmDetails, xofProvider);
            }

            public IXofFactory<KMacParameters> CreateXofFactory(KMacParameters algorithmDetails)
            {
                XofEngineProvider<KMacParameters> xofProvider = (XofEngineProvider<KMacParameters>)xofProviders[algorithmDetails.Algorithm];

                return new XofFactory<KMacParameters>(algorithmDetails, xofProvider);
            }

            public IXofFactory<ParallelHashParameters> CreateXofFactory(ParallelHashParameters algorithmDetails)
            {
                XofEngineProvider<ParallelHashParameters> xofProvider = (XofEngineProvider<ParallelHashParameters>)xofProviders[algorithmDetails.Algorithm];

                return new XofFactory<ParallelHashParameters>(algorithmDetails, xofProvider);
            }

            public IXofFactory<TupleHashParameters> CreateXofFactory(TupleHashParameters algorithmDetails)
            {
                XofEngineProvider<TupleHashParameters> xofProvider = (XofEngineProvider<TupleHashParameters>)xofProviders[algorithmDetails.Algorithm];

                return new XofFactory<TupleHashParameters>(algorithmDetails, xofProvider);
            }
        }

        /// <summary>
        /// HMAC key class.
        /// </summary>
        public class Key : SymmetricSecretKey, ICryptoServiceType<IMacFactoryService>, IServiceProvider<IMacFactoryService>
        {
            public Key(AuthenticationParameters parameterSet, byte[] bytes) : base(parameterSet, bytes)
            {
            }

            Func<IKey, IMacFactoryService> IServiceProvider<IMacFactoryService>.GetFunc(SecurityContext context)
            {
                return (key) => new HmacProvider(key as ISymmetricKey);
            }
        }

        /// <summary>
        /// KeyedXof key class.
        /// </summary>
        public class XofKey : SymmetricSecretKey, ICryptoServiceType<IXofFactoryService>, IServiceProvider<IXofFactoryService>
        {
            public XofKey(KMacParameters parameterSet, byte[] bytes) : base(parameterSet.Algorithm, bytes)
            {
            }

            Func<IKey, IXofFactoryService> IServiceProvider<IXofFactoryService>.GetFunc(SecurityContext context)
            {
                return (key) => new XofProvider(key as ISymmetricKey);
            }
        }

        private class HmacProvider : IMacFactoryService
        {
            private readonly ISymmetricKey key;

            internal HmacProvider(ISymmetricKey key)
            {
                this.key = key;
            }

            IMacFactory<A> IMacFactoryService.CreateMacFactory<A>(A algorithmDetails)
            {
                HmacEngineProvider macProvider = (HmacEngineProvider)hmacProviders[algorithmDetails.Algorithm];
                int defaultMacSize = macProvider.MacSize;

                if (key != null)
                {
                    macProvider = new KeyedHmacEngineProvider(key, macProvider);
                }

                if (algorithmDetails.MacSizeInBits != defaultMacSize * 8)
                {
                    macProvider = new TruncatedHmacEngineProvider(macProvider, algorithmDetails.MacSizeInBits);
                }

                return (IMacFactory<A>)new MacFactory<AuthenticationParameters>(algorithmDetails as AuthenticationParameters, macProvider, algorithmDetails.MacSizeInBits / 8);
            }
        }

        private class XofProvider: IXofFactoryService
		{
			private readonly ISymmetricKey key;

			internal XofProvider(ISymmetricKey key)
			{
				this.key = key;
			}

            IXofFactory<A> IXofFactoryService.CreateXofFactory<A>(A algorithmDetails)
            {
                XofEngineProvider<KMacParameters> macProvider = (XofEngineProvider<KMacParameters>)xofProviders[algorithmDetails.Algorithm];
               
                if (key != null)
                {
                    macProvider = new KeyedXofEngineProvider(key, macProvider);
                }

                return (IXofFactory<A>)new XofFactory<KMacParameters>(algorithmDetails as KMacParameters, macProvider);
            }
        }

		internal static IDigest CreateDigest(DigestAlgorithm digestAlgorithm)
		{
            if (digestProviders.Contains(digestAlgorithm))
            {
                return ((DigestEngineProvider)digestProviders[digestAlgorithm]).CreateEngine(EngineUsage.GENERAL);
            }
            return null;
		}

        internal static bool IsHMac(DigestAlgorithm hmacAlgorithm)
        {
            return hmacProviders.Contains(hmacAlgorithm);
        }

        internal static IMac CreateHmac(DigestAlgorithm hmacAlgorithm)
		{
            if (hmacAlgorithm is AuthenticationParameters)
            {
                return ((HmacEngineProvider)hmacProviders[(hmacAlgorithm as AuthenticationParameters).Algorithm]).CreateEngine(EngineUsage.GENERAL);
            }
            if (hmacAlgorithm is Parameters)
            {
                return ((HmacEngineProvider)hmacProviders[(hmacAlgorithm as Parameters).Algorithm]).CreateEngine(EngineUsage.GENERAL);
            }
            if (hmacProviders.Contains(hmacAlgorithm))
            {
                return ((HmacEngineProvider)hmacProviders[hmacAlgorithm]).CreateEngine(EngineUsage.GENERAL);
            }
            return null;
        }

        private class ShaKatTest: IBasicKatTest<IDigest>
        {
            private static byte[] stdShaVector = Strings.ToByteArray("abc");
            private readonly byte[] kat;

            internal ShaKatTest(byte[] kat)
            {
                this.kat = kat;
            }

            public bool HasTestPassed(IDigest digest)
            {
                byte[] result = Digests.DoFinal(digest, stdShaVector, 0, stdShaVector.Length);
                return Arrays.AreEqual(result, kat);
            }
        }

        private class HMacKatTest : IBasicKatTest<IMac>
        {
            private static readonly byte[] stdHMacVector = Strings.ToByteArray("what do ya want for nothing?");
            private static readonly byte[] key = Hex.Decode("4a656665");

            private readonly byte[] kat;

            internal HMacKatTest(byte[] kat)
            {
                this.kat = kat;
            }

            public bool HasTestPassed(IMac hMac)
            {
                byte[] result = Macs.DoFinal(hMac, new KeyParameter(key), stdHMacVector, 0, stdHMacVector.Length);

                return Arrays.AreEqual(result, kat);
            }
        }

        internal class XofKatTest : IBasicKatTest<IXof>
        {
            private static byte[] stdShaVector = Strings.ToByteArray("abc");
            private readonly byte[] kat;

            internal XofKatTest(byte[] kat)
            {
                this.kat = kat;
            }

            public bool HasTestPassed(IXof digest)
            {
                byte[] result = Digests.DoFinal(digest, stdShaVector, 0, stdShaVector.Length);
                return Arrays.AreEqual(result, kat);
            }
        }

        private abstract class DigestEngineProvider : IEngineProvider<IDigest>
        {
			private readonly int digestSize;

			internal DigestEngineProvider(int digestSizeInBits)
			{
				this.digestSize = digestSizeInBits / 8;
			}

			public int DigestSize
			{
				get { return digestSize; }
			}

			abstract public IDigest CreateEngine (EngineUsage usage);
		}

		private abstract class XofEngineProvider<TParams>: IParameterizedEngineProvider<IXof, TParams>
		{
			internal XofEngineProvider()
			{
			}
				
			abstract public IXof CreateEngine (EngineUsage usage, TParams parameters);
		}

		private abstract class HmacEngineProvider: IEngineProvider<IMac>
		{
			private readonly int macSizeInBits;

			internal HmacEngineProvider(int macSizeInBits)
			{
				this.macSizeInBits = macSizeInBits / 8;
			}

			public int MacSize
			{
				get { return macSizeInBits; }
			}

			abstract public IMac CreateEngine (EngineUsage usage);
		}

		private class KeyedHmacEngineProvider: HmacEngineProvider
		{
			private readonly ISymmetricKey key;
			private readonly HmacEngineProvider provider;

			internal KeyedHmacEngineProvider(ISymmetricKey key, HmacEngineProvider provider): base(provider.MacSize * 8)
			{
				this.key = key;
				this.provider = provider;
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				IMac mac = provider.CreateEngine (usage);

				if (key != null)
				{
					mac.Init(new KeyParameter(key.GetKeyBytes()));
				}

				return mac;
			}
		}

        private class KeyedXofEngineProvider : XofEngineProvider<KMacParameters>
        {
            private readonly ISymmetricKey key;
            private readonly XofEngineProvider<KMacParameters> provider;

            internal KeyedXofEngineProvider(ISymmetricKey key, XofEngineProvider<KMacParameters> provider)
            {
                this.key = key;
                this.provider = provider;
            }

            public override IXof CreateEngine(EngineUsage usage, KMacParameters parameters)
            {
                IXof kMac = provider.CreateEngine(usage, parameters);

                if (key != null)
                {
                    ((KMac)kMac).Init(new KeyParameter(key.GetKeyBytes()));
                }

                return kMac;
            }
        }

        private class TruncatedHmacEngineProvider: HmacEngineProvider
		{
			private readonly HmacEngineProvider provider;
			private readonly int macSizeInBits;

			internal TruncatedHmacEngineProvider(HmacEngineProvider provider, int macSizeInBits): base(macSizeInBits)
			{
				this.provider = provider;
				this.macSizeInBits = macSizeInBits;
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				IMac mac = provider.CreateEngine (usage);

				return new TruncatingMac(mac, macSizeInBits);
			}
		}

		private class Sha1DigestProvider: DigestEngineProvider
		{
			internal Sha1DigestProvider() : base(160)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA1, new Sha1Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha1]));
			}
		}

		private class Sha224DigestProvider: DigestEngineProvider
		{
			internal Sha224DigestProvider() : base(224)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
                return SelfTestExecutor.Validate(Algorithm.SHA224, new Sha224Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha224]));
            }
		}

		private class Sha256DigestProvider: DigestEngineProvider
		{
			internal Sha256DigestProvider() : base(256)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA256, new Sha256Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha256]));
			}
		}

		private class Sha384DigestProvider: DigestEngineProvider
		{
			internal Sha384DigestProvider() : base(384)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA384, new Sha384Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha384]));
			}
		}

		private class Sha512DigestProvider: DigestEngineProvider
		{
			internal Sha512DigestProvider() : base(512)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA512, new Sha512Digest(), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha512]));
			}
		}

		private class Sha512_224DigestProvider: DigestEngineProvider
		{
			internal Sha512_224DigestProvider() : base(224)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA512_224, new Sha512tDigest(224), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha512_224]));
			}
		}

		private class Sha512_256DigestProvider: DigestEngineProvider
		{
			internal Sha512_256DigestProvider() : base(256)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA512_256, new Sha512tDigest(256), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha512_256]));
			}
		}

		private class Sha3_224DigestProvider: DigestEngineProvider
		{
			internal Sha3_224DigestProvider() : base(224)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA3_224, new Sha3Digest(224), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha3_224]));
			}
		}

		private class Sha3_256DigestProvider: DigestEngineProvider
		{
			internal Sha3_256DigestProvider() : base(256)
			{
			}

			public override IDigest CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA3_256, new Sha3Digest(256), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha3_256]));
			}
		}

        private class Sha3_384DigestProvider : DigestEngineProvider
        {
            internal Sha3_384DigestProvider() : base(384)
            {
            }

            public override IDigest CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHA3_384, new Sha3Digest(384), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha3_384]));
            }
        }

        private class Sha3_512DigestProvider : DigestEngineProvider
        {
            internal Sha3_512DigestProvider() : base(512)
            {
            }

            public override IDigest CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHA3_512, new Sha3Digest(512), new ShaKatTest(FipsKats.Values[FipsKats.Vec.Sha3_512]));
            }
        }

        private class Shake128DigestProvider : DigestEngineProvider
        {
            internal Shake128DigestProvider() : base(256)
            {
            }

            public override IDigest CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHAKE128, new ShakeDigest(128), new XofKatTest(FipsKats.Values[FipsKats.Vec.Shake128]));
            }
        }

        private class Shake256DigestProvider : DigestEngineProvider
        {
            internal Shake256DigestProvider(): base(512)
            {
            }

            public override IDigest CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHAKE256, new ShakeDigest(256), new XofKatTest(FipsKats.Values[FipsKats.Vec.Shake256]));
            }
        }

        private class Shake128Provider: XofEngineProvider<XofParameters>
		{
			internal Shake128Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, XofParameters parameters)
			{
				return SelfTestExecutor.Validate(Algorithm.SHAKE128, new ShakeDigest(128), new XofKatTest(FipsKats.Values[FipsKats.Vec.Shake128]));
            }
        }

		private class Shake256Provider: XofEngineProvider<XofParameters>
		{
			internal Shake256Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, XofParameters parameters)
			{
				return SelfTestExecutor.Validate(Algorithm.SHAKE256, new ShakeDigest(256), new XofKatTest(FipsKats.Values[FipsKats.Vec.Shake256]));
            }
		}

        private class CShake128Provider: XofEngineProvider<CShakeParameters>
		{
			internal CShake128Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, CShakeParameters parameters)
			{
				return new CShakeDigest(128, parameters.functionString, parameters.customizationString);
            }
		}

		private class CShake256Provider: XofEngineProvider<CShakeParameters>
		{
			internal CShake256Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, CShakeParameters parameters)
			{
				return new CShakeDigest(256, parameters.functionString, parameters.customizationString);
            }
		}

		private class KMac128Provider: XofEngineProvider<KMacParameters>
        {
			internal KMac128Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, KMacParameters parameters)
			{
				return new KMac(128, parameters.MacSizeInBits,  parameters.customizationString);
            }
		}

		private class KMac256Provider: XofEngineProvider<KMacParameters>
        {
			internal KMac256Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, KMacParameters parameters)
			{
                return new KMac(256, parameters.MacSizeInBits,parameters.customizationString);
            }
		}

		private class TupleHash128Provider: XofEngineProvider<TupleHashParameters>
		{
			internal TupleHash128Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, TupleHashParameters parameters)
			{
				return new TupleHash(128, parameters.customizationString, parameters.DigestSizeInBits);
            }
		}

		private class TupleHash256Provider: XofEngineProvider<TupleHashParameters>
		{
			internal TupleHash256Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, TupleHashParameters parameters)
			{
				return new TupleHash(256, parameters.customizationString, parameters.DigestSizeInBits);
            }
		}

		private class ParallelHash128Provider: XofEngineProvider<ParallelHashParameters>
		{
			internal ParallelHash128Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, ParallelHashParameters parameters)
			{
				return new ParallelHash(128, parameters.customizationString, parameters.blockSize, parameters.DigestSizeInBits);
            }
		}

        private class ParallelHash256Provider: XofEngineProvider<ParallelHashParameters>
		{
			internal ParallelHash256Provider()
			{
			}

			public override IXof CreateEngine (EngineUsage usage, ParallelHashParameters parameters)
			{
				return new ParallelHash(256, parameters.customizationString, parameters.blockSize,parameters.DigestSizeInBits);
            }
		}

		private class Sha1HmacProvider: HmacEngineProvider
		{
			internal Sha1HmacProvider(): base(160)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA1_HMAC, new HMac(new Sha1Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha1HMac]));
            }
		}

		private class Sha224HmacProvider: HmacEngineProvider
		{
			internal Sha224HmacProvider(): base(224)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA224_HMAC, new HMac(new Sha224Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha224HMac]));
            }
		}

		private class Sha256HmacProvider: HmacEngineProvider
		{
			internal Sha256HmacProvider(): base(256)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA256_HMAC, new HMac(new Sha256Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha256HMac]));
            }
		}

		private class Sha384HmacProvider: HmacEngineProvider
		{
			internal Sha384HmacProvider(): base(384)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA384_HMAC, new HMac(new Sha384Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha384HMac]));
            }
		}

		private class Sha512HmacProvider: HmacEngineProvider
		{
			internal Sha512HmacProvider(): base(512)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA512_HMAC, new HMac(new Sha512Digest()), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha512HMac]));
            }
		}

        private class Sha512_224HmacProvider : HmacEngineProvider
        {
            internal Sha512_224HmacProvider() : base(224)
            {
            }

            public override IMac CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHA512_224_HMAC, new HMac(new Sha512tDigest(224)), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha512_224HMac]));
            }
        }

        private class Sha512_256HmacProvider : HmacEngineProvider
        {
            internal Sha512_256HmacProvider() : base(256)
            {
            }

            public override IMac CreateEngine(EngineUsage usage)
            {
                return SelfTestExecutor.Validate(Algorithm.SHA512_256_HMAC, new HMac(new Sha512tDigest(256)), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha512_256HMac]));
            }
        }

		private class Sha3_224HmacProvider: HmacEngineProvider
		{
			internal Sha3_224HmacProvider(): base(224)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA3_224_HMAC, new HMac(new Sha3Digest(224)), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha3_224HMac]));
            }
		}

		private class Sha3_256HmacProvider: HmacEngineProvider
		{
			internal Sha3_256HmacProvider(): base(256)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA3_256_HMAC, new HMac(new Sha3Digest(256)), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha3_256HMac]));
            }
		}

		private class Sha3_384HmacProvider: HmacEngineProvider
		{
			internal Sha3_384HmacProvider(): base(384)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA3_384_HMAC, new HMac(new Sha3Digest(384)), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha3_384HMac]));
            }
		}

		private class Sha3_512HmacProvider: HmacEngineProvider
		{
			internal Sha3_512HmacProvider(): base(512)
			{
			}

			public override IMac CreateEngine (EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Algorithm.SHA3_512_HMAC, new HMac(new Sha3Digest(512)), new HMacKatTest(FipsKats.Values[FipsKats.Vec.Sha3_512HMac]));
            }
		}
    }
}

