using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Crypto.Internal;
using Org.BouncyCastle.Crypto.Internal.Signers;
using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Crypto.Internal.Generators;
using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.General
{
    /// <summary>
    /// Source class for Edwards Curve EC Signature Algorithms
    /// </summary>
    public class EdEC
	{
        internal static readonly byte[] ZERO_CONTEXT = new byte[0];

        private EdEC()
        {

        }

        public static class Algorithm
        {
            public static readonly GeneralAlgorithm Ed448 = new GeneralAlgorithm("Ed448", AlgorithmMode.Ed448);
            public static readonly GeneralAlgorithm Ed25519 = new GeneralAlgorithm("Ed25519", AlgorithmMode.Ed25519);
        }

        public static readonly ParametersWithContext Ed448 = new ParametersWithContext(Algorithm.Ed448);
        public static readonly Parameters Ed25519 = new Parameters(Algorithm.Ed25519);

        public static readonly int Ed448PublicKeySize = Ed448PublicKeyParameters.KeySize;
        public static readonly int Ed25519PublicKeySize = Ed25519PublicKeyParameters.KeySize;

        public static readonly int Ed448PrivateKeySize = Ed448PrivateKeyParameters.KeySize;
        public static readonly int Ed25519PrivateKeySize = Ed25519PrivateKeyParameters.KeySize;

        public class Parameters: IParameters<GeneralAlgorithm>, IGenerationServiceType<KeyPairGenerator>, IGenerationService<KeyPairGenerator>
        {
            private readonly GeneralAlgorithm algorithm;

			internal Parameters(GeneralAlgorithm algorithm)
			{
                this.algorithm = algorithm;
			}

            public GeneralAlgorithm Algorithm
            {
                get { return this.algorithm;  }
            }

            Func<IParameters<Crypto.Algorithm>, SecureRandom, KeyPairGenerator> IGenerationService<KeyPairGenerator>.GetFunc(SecurityContext context)
            {
                return (parameters, random) => new KeyPairGenerator(parameters as Parameters, random);
            }
        }

        public class ParametersWithContext: Parameters
        {
            internal readonly byte[] context;

            internal ParametersWithContext(GeneralAlgorithm algorithm) : base(algorithm)
            {
                this.context = ZERO_CONTEXT;
            }

            internal ParametersWithContext(GeneralAlgorithm algorithm, byte[] context): base(algorithm)
            {
                this.context = Arrays.Clone(context);
            }

            public byte[] GetContext()
            {
                return Arrays.Clone(context);
            }

            public ParametersWithContext WithContext(byte[] context)
            {
                return new ParametersWithContext(this.Algorithm, context);
            }
        }

        /// <summary>
        /// Key pair generator for EdDSA. Create one these via CryptoServicesRegistrar.CreateGenerator() using the KeyGenerationParameters
        /// object as the key.
        /// </summary>
        public class KeyPairGenerator : AsymmetricKeyPairGenerator<Parameters, AsymmetricEdDsaPublicKey, AsymmetricEdDsaPrivateKey>
        {
            private readonly bool is25519;
            private readonly GeneralAlgorithm alg;
            private readonly IAsymmetricCipherKeyPairGenerator engine;

            /// <summary>
            /// Construct a key pair generator for EC keys,
            /// </summary>
            /// <param name="algorithm">Algorithm for the generated key.</param>
            /// <param name="random">A source of randomness for calculating the private value.</param>
            internal KeyPairGenerator(Parameters algorithm, SecureRandom random): base(algorithm)
            {
                Utils.ApprovedModeCheck("key pair generator", algorithm.Algorithm);

                this.alg = algorithm.Algorithm;

                if (this.alg.Equals(Algorithm.Ed25519))
                {
                    this.is25519 = true;
                    this.engine = new Ed25519KeyPairGenerator();
                    this.engine.Init(new Ed25519KeyGenerationParameters(random));
                }
                else if (this.alg.Equals(Algorithm.Ed448))
                {
                    this.is25519 = false;
                    this.engine = new Ed448KeyPairGenerator();
                    this.engine.Init(new Ed448KeyGenerationParameters(random));
                }
                else
                {
                    throw new ArgumentException("algorithm not recoginized: " + this.alg);
                }
            }

            /// <summary>
            /// Generate a new EdDSA key pair.
            /// </summary>
            /// <returns>A new AsymmetricKeyPair containing an EdDSA key pair.</returns>
            public override AsymmetricKeyPair<AsymmetricEdDsaPublicKey, AsymmetricEdDsaPrivateKey> GenerateKeyPair()
            {
                AsymmetricCipherKeyPair kp = engine.GenerateKeyPair();

                if (this.is25519)
                {
                    Internal.Parameters.Ed25519PublicKeyParameters pubKey = (Internal.Parameters.Ed25519PublicKeyParameters)kp.Public;
                    Internal.Parameters.Ed25519PrivateKeyParameters prvKey = (Internal.Parameters.Ed25519PrivateKeyParameters)kp.Private;

                    return new AsymmetricKeyPair<AsymmetricEdDsaPublicKey, AsymmetricEdDsaPrivateKey>(
                        new AsymmetricEdDsaPublicKey(this.alg, pubKey.GetEncoded()), new AsymmetricEdDsaPrivateKey(this.alg, prvKey.GetEncoded(), pubKey.GetEncoded()));
                }
                else
                {
                    Internal.Parameters.Ed448PublicKeyParameters pubKey = (Internal.Parameters.Ed448PublicKeyParameters)kp.Public;
                    Internal.Parameters.Ed448PrivateKeyParameters prvKey = (Internal.Parameters.Ed448PrivateKeyParameters)kp.Private;

                    return new AsymmetricKeyPair<AsymmetricEdDsaPublicKey, AsymmetricEdDsaPrivateKey>(
                        new AsymmetricEdDsaPublicKey(this.alg, pubKey.GetEncoded()), new AsymmetricEdDsaPrivateKey(this.alg, prvKey.GetEncoded(), pubKey.GetEncoded()));
                }
            }
        }

        internal class SignerProvider : IEngineProvider<ISigner>
        {
            private readonly Parameters parameters;
            private readonly ICipherParameters sigParams;

            internal SignerProvider(Parameters parameters, IKey key)
            {
                this.parameters = parameters;
                if (key is AsymmetricEdDsaPublicKey)
                {
                    this.sigParams = GetPublicKeyParameters(parameters.Algorithm, (AsymmetricEdDsaPublicKey)key);
                }
                else
                {
                    this.sigParams = GetPrivateKeyParameters(parameters.Algorithm, (AsymmetricEdDsaPrivateKey)key);
                }
            }

            public ISigner CreateEngine(EngineUsage usage)
            {
                ISigner sig;
                if (parameters.Algorithm.Equals(Algorithm.Ed25519))
                {
                    sig = new Ed25519Signer();
                }
                else
                {
                    if (parameters is ParametersWithContext)
                    {
                        sig = new Ed448Signer(((ParametersWithContext)parameters).context);
                    }
                    else
                    {
                        sig = new Ed448Signer(ZERO_CONTEXT);
                    }
                }

                sig.Init((usage == EngineUsage.SIGNING), sigParams);

                return sig;
            }
        }

        internal static Internal.AsymmetricKeyParameter GetPublicKeyParameters(GeneralAlgorithm alg, AsymmetricEdDsaPublicKey k)
        {
            if (alg.Equals(Algorithm.Ed25519))
            {
                return new Ed25519PublicKeyParameters(k.GetPublicData());
            }
            else
            {
                return new Ed448PublicKeyParameters(k.GetPublicData());
            }
        }

        internal static Internal.AsymmetricKeyParameter GetPrivateKeyParameters(GeneralAlgorithm alg, AsymmetricEdDsaPrivateKey k)
        {
            if (alg.Equals(Algorithm.Ed25519))
            {
                return new Ed25519PrivateKeyParameters(k.GetSecret());
            }
            else
            {
                return new Ed448PrivateKeyParameters(k.GetSecret());
            }
        }
    }
}
