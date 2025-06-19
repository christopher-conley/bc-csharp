using System.Collections.Generic;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Agreement;
using Org.BouncyCastle.Crypto.Internal.Generators;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Crypto.Fips
{
	/**
	 * Source class for FIPS approved mode Diffie-Hellman implementations.
	 */
	public class FipsDH
	{
	    private static readonly int MIN_FIPS_KEY_STRENGTH = 2048;       // 112 bits of security

	    static readonly IEngineProvider<DHBasicAgreement> AGREEMENT_PROVIDER;

		/// <summary>
		/// Basic Diffie-Hellman algorithm marker, can be used for creating general purpose Diffie-Hellman keys.
		/// </summary>
		public static readonly FipsAlgorithm Alg = new FipsAlgorithm("DH", AlgorithmMode.DH);

		/// <summary>
		/// Diffie-Hellman algorithm parameter source.
		/// </summary>
		public static readonly AgreementParameters DH = new AgreementParameters(new FipsAlgorithm(Alg, AlgorithmMode.DH));

	    static FipsDH()
	    {
		AGREEMENT_PROVIDER = new DHProvider();

		// FSM_STATE:3.DH.0,"FF AGREEMENT KAT", "The module is performing FF Key Agreement verify KAT self-test"
		// FSM_TRANS:3.DH.0,"POWER ON SELF-TEST", "FF AGREEMENT KAT", "Invoke FF Diffie-Hellman/MQV  KAT self-test"
		AGREEMENT_PROVIDER.CreateEngine(EngineUsage.GENERAL);
		// FSM_TRANS:3.DH.1,"FF AGREEMENT KAT", "POWER ON SELF-TEST", "FF Diffie-Hellman/MQV KAT self-test successful completion"

		// FSM_STATE:3.DH.1,"KAS CVL Primitive 'Z' computation KAT", "The module is performing KAS CVL Primitive 'Z' computation KAT verify KAT self-test"
		// FSM_TRANS:3.DH.2,"POWER ON SELF-TEST", "KAS CVL Primitive 'Z' computation KAT", "Invoke KAS CVL Primitive 'Z' computation KAT self-test"
		ffPrimitiveZTest();
		// FSM_TRANS:3.DH.3,"KAS CVL Primitive 'Z' computation KAT", "POWER ON SELF-TEST", "KAS CVL Primitive 'Z' computation KAT self-test successful completion"
	    }

	/// <summary>
	/// DHDomainParametersID for the NIST defined DH domain parameters.
	/// </summary>
	public class DomainParams
	{
		public static readonly IDHDomainParametersID ffdhe2048 = new DomainParametersID("ffdhe2048");
		public static readonly IDHDomainParametersID ffdhe3072 = new DomainParametersID("ffdhe3072");
		public static readonly IDHDomainParametersID ffdhe4096 = new DomainParametersID("ffdhe4096");
		public static readonly IDHDomainParametersID ffdhe6144 = new DomainParametersID("ffdhe6144");
		public static readonly IDHDomainParametersID ffdhe8192 = new DomainParametersID("ffdhe8192");
		public static readonly IDHDomainParametersID modp2048 = new DomainParametersID("modp2048");
		public static readonly IDHDomainParametersID modp3072 = new DomainParametersID("modp3072");
		public static readonly IDHDomainParametersID modp4096 = new DomainParametersID("modp4096");
		public static readonly IDHDomainParametersID modp6144 = new DomainParametersID("modp6144");
		public static readonly IDHDomainParametersID modp8192 = new DomainParametersID("modp8192");

		internal class DomainParametersID : IDHDomainParametersID
		{
			private string name;

			internal DomainParametersID(string name)
			{
				this.name = name;
			}

			public string ParametersName
			{
				get
				{
					return name;
				}
			}
		}

		/// <summary>
		/// Return a list of the common NIST curves.
		/// </summary>
		/// <returns>A list of the common NIST curves.</returns>
		public static List<IDHDomainParametersID> Values()
		{
			List<IDHDomainParametersID> v = new List<IDHDomainParametersID>();

			v.Add(ffdhe2048);
			v.Add(ffdhe3072);
			v.Add(ffdhe4096);
			v.Add(ffdhe6144);
			v.Add(ffdhe8192);
			v.Add(modp2048);
			v.Add(modp3072);
			v.Add(modp4096);
			v.Add(modp6144);
			v.Add(modp8192);

			return v;
		}
	}

		/// <summary>
		/// Parameters for DH key agreement.
		/// </summary>
		public class AgreementParameters : AgreementParameters<FipsAlgorithm, FipsDigestAlgorithm, FipsPrfAlgorithm, FipsKdfAlgorithm>
		{
			/// <summary>
			/// Default constructor which specifies returning the raw secret on agreement calculation.
			/// </summary>
			/// <param name="agreementAlgorithm">The agreement algorithm.</param>
			internal AgreementParameters(FipsAlgorithm agreementAlgorithm) : this(agreementAlgorithm, new CopyKMGenerator())
			{
			}

			private AgreementParameters(FipsAlgorithm agreementAlgorithm, IKMGenerator kmGenerator) : base(agreementAlgorithm, kmGenerator)
			{
			}

			/// <summary>
			/// Add a key material generator for doing final processing on the agreed value.
			/// </summary>
			/// <returns>A new parameter set, including key material generator.</returns>
			/// <param name="kmGenerator">The key material generator to use.</param>
			public AgreementParameters WithKeyMaterialGenerator(IKMGenerator kmGenerator)
			{
				if (kmGenerator == null)
				{
					throw new ArgumentException("kmGenerator cannot be null");
				}
				return new AgreementParameters(Algorithm, kmGenerator);
			}
		}

		private class CopyKMGenerator : IKMGenerator
		{
			public byte[] Generate(byte[] agreed)
			{
				return Arrays.Clone(agreed);
			}
		}

		/// <summary>
		/// Parameters for DH key pair generation.
		/// </summary>
		public class KeyGenerationParameters : FipsParameters, IGenerationServiceType<KeyPairGenerator>, IGenerationService<KeyPairGenerator>
		{
			private readonly DHDomainParameters domainParameters;

			/// <summary>
			/// Constructor for the default algorithm ID.
			/// </summary>
			/// <param name="domainParameters">DH domain parameters representing the domain parameters for any generated keys will be for.</param>
			public KeyGenerationParameters(DHDomainParameters domainParameters) : this(Alg, domainParameters)
			{
			}

			/// <summary>
			/// Constructor for the default algorithm ID.
			/// </summary>
			/// <param name="domainParametersID">DH named domain parameters ID representing the domain parameters for any generated keys will be for.</param>
			public KeyGenerationParameters(IDHDomainParametersID domainParametersID) : this(Alg, DHDomainParametersIndex.LookupDomainParameters(domainParametersID))
			{
			}

			public KeyGenerationParameters For(AgreementParameters agreementUsage)
			{
				return new KeyGenerationParameters(agreementUsage.Algorithm, this.domainParameters);
			}

			KeyGenerationParameters(FipsAlgorithm algorithm, DHDomainParameters domainParameters) : base(algorithm)
			{
				this.domainParameters = domainParameters;
			}

			/// <summary>
			/// Return the DH domain parameters for this object.
			/// </summary>
			/// <value>The DH domain parameter set.</value>
			public DHDomainParameters DomainParameters
			{
				get
				{
					return domainParameters;
				}
			}

			Func<IParameters<Algorithm>, SecureRandom, KeyPairGenerator> IGenerationService<KeyPairGenerator>.GetFunc(SecurityContext context)
			{
				return (parameters, random) => new KeyPairGenerator(parameters as KeyGenerationParameters, random);
			}
		}

		/// <summary>
		/// Key pair generator for DH. Create one these via CryptoServicesRegistrar.CreateGenerator() using the KeyGenerationParameters
		/// object as the key.
		/// </summary>
		public class KeyPairGenerator : AsymmetricKeyPairGenerator<FipsParameters, AsymmetricDHPublicKey, AsymmetricDHPrivateKey>
		{
			private readonly DHDomainParameters domainParameters;
			private readonly DHKeyGenerationParameters param;
			private readonly DHKeyPairGenerator engine = new DHKeyPairGenerator(false);

			/// <summary>
			/// Construct a key pair generator for EC keys,
			/// </summary>
			/// <param name="keyGenParameters">Domain parameters and algorithm for the generated key.</param>
			/// <param name="random">A source of randomness for calculating the private value.</param>
			internal KeyPairGenerator(KeyGenerationParameters keyGenParameters, SecureRandom random) : base(keyGenParameters)
			{
				if (CryptoServicesRegistrar.IsInApprovedOnlyMode())
				{
					int sizeInBits = keyGenParameters.DomainParameters.P.BitLength;
					if (sizeInBits < MIN_FIPS_KEY_STRENGTH)
					{
						throw new CryptoUnapprovedOperationError("Attempt to create key of less than " + MIN_FIPS_KEY_STRENGTH + " bits", keyGenParameters.Algorithm);
					}

					Utils.ValidateKeyPairGenRandom(random, Utils.GetAsymmetricSecurityStrength(sizeInBits), Alg);
				}

				this.param = new DHKeyGenerationParameters(random, getDomainParams(keyGenParameters.DomainParameters));
				this.domainParameters = keyGenParameters.DomainParameters;
				this.engine.Init(param);
			}

			/// <summary>
			/// Generate a new DH key pair.
			/// </summary>
			/// <returns>A new AsymmetricKeyPair containing an DH key pair.</returns>
			public override AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey> GenerateKeyPair()
			{
				AsymmetricCipherKeyPair kp = engine.GenerateKeyPair();

				Internal.Parameters.DHPublicKeyParameters pubKey = (Internal.Parameters.DHPublicKeyParameters)kp.Public;
				Internal.Parameters.DHPrivateKeyParameters prvKey = (Internal.Parameters.DHPrivateKeyParameters)kp.Private;

				FipsAlgorithm algorithm = this.Parameters.Algorithm;

				// FSM_STATE:5.5, "DH PAIRWISE CONSISTENCY TEST", "The module is performing DH Pairwise Consistency self-test"
				// FSM_TRANS:5.DH.0,"CONDITIONAL TEST", "DH PAIRWISE CONSISTENCY TEST", "Invoke DH Pairwise Consistency test"
				validateKeyPair(algorithm, kp);
				// FSM_TRANS:5.DH.1,"DH PAIRWISE CONSISTENCY TEST", "CONDITIONAL TEST", "DH Pairwise Consistency test successful"

				return new AsymmetricKeyPair<AsymmetricDHPublicKey, AsymmetricDHPrivateKey>(new AsymmetricDHPublicKey(algorithm, domainParameters, pubKey.Y), new AsymmetricDHPrivateKey(algorithm, domainParameters, prvKey.X));
			}
		}

		internal class AgreementCalculator : IAgreementCalculator<AgreementParameters>
		{
			private readonly IBasicAgreement agreement;
			private readonly AgreementParameters parameters;

			internal AgreementCalculator(AgreementParameters parameters, IKey dhPrivateKey)
			{
				this.agreement = AGREEMENT_PROVIDER.CreateEngine(EngineUsage.GENERAL);

				agreement.Init(getLwKey((AsymmetricDHPrivateKey)dhPrivateKey));

				this.parameters = parameters;
			}

			public AgreementParameters AlgorithmDetails
			{
				get { return parameters; }
			}

			public byte[] Calculate(IAsymmetricPublicKey publicKey)
			{
				DHDomainParameters domainParams = ((AsymmetricDHPublicKey)publicKey).DomainParameters;

				byte[] zBytes = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(),
					agreement.CalculateAgreement(getLwPubKey((AsymmetricDHPublicKey)publicKey)));

				byte[] keyMaterial = parameters.KeyMaterialGenerator.Generate(zBytes);

				// ZEROIZE
				Arrays.Fill(zBytes, (byte)0);

				return keyMaterial;
			}
		}

	    private static void validateKeyPair(FipsAlgorithm algorithm, AsymmetricCipherKeyPair keyPair)
	    {
			switch (algorithm.Mode)
			{
			case AlgorithmMode.DH:
					SelfTestExecutor.Validate(algorithm, keyPair, new DHConsistencyTest());
				break;
			default:
				throw new InvalidOperationException("Unhandled DH algorithm: " + algorithm.Name);
			}
		}

		private class DHConsistencyTest : IConsistencyTest<AsymmetricCipherKeyPair>
		{
			public bool HasTestPassed(AsymmetricCipherKeyPair kp)
			{
			    DHBasicAgreement agreement = new DHBasicAgreement();

			    agreement.Init(kp.Private);

			    BigInteger agree1 = agreement.CalculateAgreement(kp.Public);

			    AsymmetricCipherKeyPair testKP = getTestKeyPair(kp);

			    agreement.Init(testKP.Private);

			    BigInteger agree2 = agreement.CalculateAgreement(testKP.Public);

			    agreement.Init(kp.Private);

			    BigInteger agree3 = agreement.CalculateAgreement(testKP.Public);

			    agreement.Init(testKP.Private);

			    BigInteger agree4 = agreement.CalculateAgreement(kp.Public);

			    return !agree1.Equals(agree2) && !agree1.Equals(agree3) && agree3.Equals(agree4);
			}
		}


		class DHProvider : IEngineProvider<DHBasicAgreement>
		{
			public DHBasicAgreement CreateEngine(EngineUsage usage)
			{
				return SelfTestExecutor.Validate(Alg, new DHBasicAgreement(), new DHKatTest());
			}
		}

		class DHKatTest : VariantKatTest<DHBasicAgreement>
		{
			internal override void Evaluate(DHBasicAgreement agreement)
			{
				AsymmetricCipherKeyPair kp = getKATKeyPair();

				AsymmetricCipherKeyPair testOther = getTestKeyPair(kp);

				agreement.Init(kp.Private);

				BigInteger expected = new BigInteger(1, FipsKats.Values[FipsKats.Vec.DHHealthVec]);
	
				if (!expected.Equals(agreement.CalculateAgreement(testOther.Public)))
				{
					Fail("KAT ECDH agreement not verified");
				}
			}
		}

		private static void ffPrimitiveZTest()
	    {
			SelfTestExecutor.Validate(Alg, new PrimFFTest());
	    }

		class PrimFFTest : VariantInternalKatTest
		{ 
			internal PrimFFTest() : base(Alg)
			{

			}
			internal override void Evaluate()
			{
				AsymmetricCipherKeyPair kp = getKATKeyPair();

				DHPrivateKeyParameters priv = (DHPrivateKeyParameters)kp.Private;
				DHPublicKeyParameters pub = (DHPublicKeyParameters)kp.Public;

				if (!pub.Y.Equals(priv.Parameters.G.ModPow(priv.X, priv.Parameters.P)))
				{
					Fail("FF primitive 'Z' computation failed");
				}
			}
		}

		private static AsymmetricCipherKeyPair getKATKeyPair()
	    {
			DHDomainParameters dhDp = DHDomainParametersIndex.LookupDomainParameters(DomainParams.ffdhe2048);

			DHParameters dhParameters = new DHParameters(dhDp.P, dhDp.G, dhDp.Q);
			BigInteger x = new BigInteger("80d54802e42ce811d122ce2657c303013fc33c2f08f8ff1a9c4ebfd1", 16);
			BigInteger y = new BigInteger(
								  "f9a4d8edb52efa7ffd00bc2e632b79c69eba8949f7ba23a6feb2d27278e96cbd7fe158484286c07f91144a268539eeffb306844898"
								+ "c5efa845070489bcdc756c6858dcb242629f91b2714a33c0efebcb4b0832dba33b12db491dcded86f497094a52a3091a4bdf832d4f"
								+ "36cb0cd7ab05e24b2adea4d746806d9776cebe45b0938c8a7f323db0497f865e8d992839ce018d54b68c5808a97fb035c83c304690"
								+ "e6fff83dfd13be0186bdf0531cc416f9189fe87b1c92ce569578e9f55c874c0111a1e155f4dd876069424d38c94beb47f890d082eb"
								+ "9183a7ce3c6819c420ca91ba969549835314df899fc766ac2acc9d6b9de5b0a9570ca4cfb6187e049fbe6f10", 16);
			return new AsymmetricCipherKeyPair(new DHPublicKeyParameters(y, dhParameters), new DHPrivateKeyParameters(x, dhParameters));
	    }

	    private static AsymmetricCipherKeyPair getTestKeyPair(AsymmetricCipherKeyPair kp)
	    {
			DHPrivateKeyParameters privKey = (DHPrivateKeyParameters)kp.Private;
			DHParameters dhParams = privKey.Parameters;

			BigInteger testD = privKey.X.Multiply(BigInteger.ValueOf(7)).Mod(privKey.X);

			if (testD.CompareTo(BigInteger.ValueOf(2)) < 0)
			{
				testD = new BigInteger("0102030405060708090a0b0c0d0e0f101112131415161718", 16);
			}

			DHPrivateKeyParameters testPriv = new DHPrivateKeyParameters(testD, dhParams);
			DHPublicKeyParameters testPub = new DHPublicKeyParameters(dhParams.G.ModPow(testD, dhParams.P), dhParams);

			return new AsymmetricCipherKeyPair(testPub, testPriv);
	    }

	    private static DHParameters getDomainParams(Org.BouncyCastle.Crypto.Asymmetric.DHDomainParameters dhParameters)
	    {
			return new DHParameters(dhParameters.P, dhParameters.G, dhParameters.Q, dhParameters.M, dhParameters.L, dhParameters.J);
	    }

	    private static DHPrivateKeyParameters getLwKey(AsymmetricDHPrivateKey privKey)
	    {
			return new DHPrivateKeyParameters(privKey.X, getDomainParams(privKey.DomainParameters));
	    }
		private static DHPublicKeyParameters getLwPubKey(AsymmetricDHPublicKey pubKey)
		{
			return new DHPublicKeyParameters(pubKey.Y, getDomainParams(pubKey.DomainParameters));
		}

	}
}
