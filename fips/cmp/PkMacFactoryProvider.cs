using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Iana;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crmf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cmp
{
   
    public class PKMacFactory : IMacFactory<AlgorithmIdentifier>
    {
        protected readonly PbmParameter parameters;
        private readonly byte[] key;

        public PKMacFactory(byte[] key, PbmParameter parameters)
        {
            this.key = Arrays.Clone(key);
            this.parameters = parameters;
        }

        public virtual AlgorithmIdentifier AlgorithmDetails
        {
            get { return new AlgorithmIdentifier(CmpObjectIdentifiers.passwordBasedMac, parameters); }
        }

        public int MacLength {
            get
            {
                var digestAlgorithm = (DigestAlgorithm)Utils.digestTable[parameters.Mac.Algorithm];
                return (int)Utils.digestSize[digestAlgorithm];
            }
        }

        public virtual IStreamCalculator<IBlockResult> CreateCalculator()
        {
            return new PkixMacFactory(AlgorithmDetails, key).CreateCalculator();
        }
    }

   
    

    public class PKMacBuilder
    {
        private readonly AlgorithmIdentifier owf;
        private readonly AlgorithmIdentifier mac;
        private readonly IPKMacPrimitivesProvider provider;
        private SecureRandom random;
        private PbmParameter parameters;
        private int iterationCount;
        private int saltLength;
        //private byte[] salt;
        private readonly int maxIterations;

        /// <summary>
        /// Default, IterationCount = 1000, OIW=IdSha1, Mac=HmacSHA1
        /// </summary>
        public PKMacBuilder() :
            this(new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), 1000, new AlgorithmIdentifier(IanaObjectIdentifiers.HmacSha1, DerNull.Instance), new DefaultPKMacPrimitivesProvider())
        {
        }

        /// <summary>
        /// Defaults with IPKMacPrimitivesProvider
        /// </summary>
        /// <param name="provider"></param>
        public PKMacBuilder(IPKMacPrimitivesProvider provider) :
            this(new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1), 1000, new AlgorithmIdentifier(IanaObjectIdentifiers.HmacSha1, DerNull.Instance), provider)
        {
        }

        /// <summary>
        /// Create.
        /// </summary>
        /// <param name="provider">The Mac provider</param>
        /// <param name="digestAlgorithmIdentifier">Digest Algorithm Id</param>
        /// <param name="macAlgorithmIdentifier">Mac Algorithm Id</param>
        public PKMacBuilder(IPKMacPrimitivesProvider provider, AlgorithmIdentifier digestAlgorithmIdentifier, AlgorithmIdentifier macAlgorithmIdentifier) :
            this(digestAlgorithmIdentifier, 1000, macAlgorithmIdentifier, provider)
        {
        }

        /// <summary>
        /// Create a PKMAC builder enforcing a ceiling on the maximum iteration count.
        /// </summary>
        /// <param name="provider">supporting calculator</param>
        /// <param name="maxIterations">max allowable value for iteration count.</param>
        public PKMacBuilder(IPKMacPrimitivesProvider provider, int maxIterations)
        {
            this.provider = provider;
            this.maxIterations = maxIterations;
        }


        private PKMacBuilder(AlgorithmIdentifier digestAlgorithmIdentifier, int iterationCount, AlgorithmIdentifier macAlgorithmIdentifier, IPKMacPrimitivesProvider provider)
        {
            this.iterationCount = iterationCount;
            this.mac = macAlgorithmIdentifier;
            this.owf = digestAlgorithmIdentifier;
            this.provider = provider;
        }

        /**
         * Set the salt length in octets.
         *
         * @param saltLength length in octets of the salt to be generated.
         * @return the generator
         */
        public PKMacBuilder SetSaltLength(int saltLength)
        {
            if (saltLength < 8)
            {
                throw new ArgumentException("salt length must be at least 8 bytes");
            }

            this.saltLength = saltLength;

            return this;
        }

        /// <summary>
        /// Set the iteration count.
        /// </summary>
        /// <param name="iterationCount">the iteration count.</param>
        /// <returns>this</returns>
        /// <exception cref="ArgumentException">if iteration count is less than 100</exception>
        public PKMacBuilder SetIterationCount(int iterationCount)
        {
            if (iterationCount < 100)
            {
                throw new ArgumentException("iteration count must be at least 100");
            }
            CheckIterationCountCeiling(iterationCount);

            this.iterationCount = iterationCount;

            return this;
        }

        /// <summary>
        /// Set PbmParameters
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>this</returns>
        public PKMacBuilder SetParameters(PbmParameter parameters)
        {
            CheckIterationCountCeiling(parameters.IterationCount.IntValueExact);

            this.parameters = parameters;

            return this;
        }

        /// <summary>
        /// The Secure random
        /// </summary>
        /// <param name="random">The random.</param>
        /// <returns>this</returns>
        public PKMacBuilder SetSecureRandom(SecureRandom random)
        {
            this.random = random;

            return this;
        }

        /// <summary>
        /// Build an IMacFactory.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>IMacFactory</returns>
        public IMacFactory<AlgorithmIdentifier> Build(char[] password)
        {
            if (parameters != null)
            {
                return GenCalculator(parameters, password);
            }
            else
            {
                byte[] salt = new byte[saltLength];

                if (random == null)
                {
                    this.random = new SecureRandom();
                }

                random.NextBytes(salt);

                return GenCalculator(new PbmParameter(salt, owf, iterationCount, mac), password);
            }
        }

        private void CheckIterationCountCeiling(int iterationCount)
        {
            if (maxIterations > 0 && iterationCount > maxIterations)
                throw new ArgumentException("iteration count exceeds limit (" + iterationCount + " > " + maxIterations + ")");
        }

        private IMacFactory<AlgorithmIdentifier> GenCalculator(PbmParameter parameters, char[] password)
        {
            // From RFC 4211
            //
            //   1.  Generate a random salt value S
            //
            //   2.  Append the salt to the pw.  K = pw || salt.
            //
            //   3.  Hash the value of K.  K = HASH(K)
            //
            //   4.  Iter = Iter - 1.  If Iter is greater than zero.  Goto step 3.
            //
            //   5.  Compute an HMAC as documented in [HMAC].
            //
            //       MAC = HASH( K XOR opad, HASH( K XOR ipad, data) )
            //
            //       Where opad and ipad are defined in [HMAC].
            byte[] pw = Strings.ToUtf8ByteArray(password);
            byte[] salt = parameters.Salt.GetOctets();
            byte[] K = new byte[pw.Length + salt.Length];

            Array.Copy(pw, 0, K, 0, pw.Length);
            Array.Copy(salt, 0, K, pw.Length, salt.Length);

            var digestFactory = provider.CreateDigest(parameters.Owf);

            var streamCalculator = digestFactory.CreateCalculator();

           


           // IDigest digest = provider.CreateDigest(parameters.Owf);

            int iter = parameters.IterationCount.IntValueExact;

            //streamCalculator.Stream.Write(K,0,K.Length);
            //digest.BlockUpdate(K, 0, K.Length);


            //K = new byte[  digest.GetDigestSize()];
            //digest.DoFinal(K, 0);


            K = UpdateThenFinal(streamCalculator, K);

            

            while (--iter > 0)
            {
                K = UpdateThenFinal(streamCalculator, K);
                //digest.BlockUpdate(K, 0, K.Length);

                //digest.DoFinal(K, 0);
            }

            //byte[] key = K;

            var alg = new AlgorithmIdentifier(CmpObjectIdentifiers.passwordBasedMac, parameters);

            return new PkixMacFactory(alg,K);
        }

        private byte[] UpdateThenFinal(IStreamCalculator<IBlockResult> calculator, byte[] k)
        {
            calculator.Stream.Write(k,0,k.Length);        
            k = calculator.GetResult().Collect(); // TODO check for digest reset!
            return k;
        }

    }


}