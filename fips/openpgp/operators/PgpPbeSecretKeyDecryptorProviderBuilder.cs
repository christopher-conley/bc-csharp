using System;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.OpenPgp.Operators.Parameters;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.OpenPgp.Operators
{
    public class PgpPbeSecretKeyDecryptorProviderBuilder
    {
        public IPbeSecretKeyDecryptorProvider Build(char[] passPhrase)
        {
            return new SecretKeyDecryptorProvider(passPhrase);
        }

        private class SecretKeyDecryptorProvider : IPbeSecretKeyDecryptorProvider
        {
            private readonly char[] passPhrase;

            public SecretKeyDecryptorProvider(char[] passPhrase)
            {
                this.passPhrase = passPhrase;
            }

            public IDigestFactory<PgpDigestTypeIdentifier> CreateDigestFactory(PgpDigestTypeIdentifier algorithmDetails)
            {
                throw new NotImplementedException();
            }

            public IKeyUnwrapper<PgpPbeKeyEncryptionParameters> CreateKeyUnwrapper(PgpPbeKeyEncryptionParameters algorithmDetails)
            {
                S2k s2k = algorithmDetails.S2k;

                byte[] key = PgpUtilities.MakeKeyFromPassPhrase(new PgpSha1DigestFactory(), algorithmDetails.Algorithm, s2k, passPhrase);

                return new SecretKeyDecryptor(algorithmDetails.Algorithm, key, algorithmDetails.GetIV(), s2k, new PgpSha1DigestFactory());
            }
        }

        private class SecretKeyDecryptor
            : IKeyUnwrapper<PgpPbeKeyEncryptionParameters>
        {
            private readonly byte[] iv;
            private readonly SymmetricKeyAlgorithmTag symAlg;
            //private readonly byte[] key;
            private readonly S2k s2k;
            private readonly IDigestFactory<PgpDigestTypeIdentifier> mChecksumCalculatorFactory;

            private readonly ICipherBuilder<FipsTripleDes.ParametersWithIV> cipherBuilder;

            internal SecretKeyDecryptor(SymmetricKeyAlgorithmTag symAlg, byte[] key, byte[] iv, S2k s2k,
                IDigestFactory<PgpDigestTypeIdentifier> checksumCalculatorFactory)
            {
                FipsTripleDes.ParametersWithIV parameters = FipsTripleDes.Cfb64.WithIV(iv);

                this.iv = iv;
                this.symAlg = symAlg;
                //this.key = key;
                this.s2k = s2k;
                //this.mChecksumCalculatorFactory = checksumCalculatorFactory;

                this.cipherBuilder = CryptoServicesRegistrar.CreateService(new FipsTripleDes.Key(key))
                    .CreateDecryptorBuilder(parameters);
            }

            public PgpPbeKeyEncryptionParameters AlgorithmDetails
            {
                get { return new PgpPbeKeyEncryptionParameters(symAlg, s2k, iv); }
            }

            public IBlockResult Unwrap(byte[] cipherText, int offset, int length)
            {
                MemoryOutputStream mOut = new MemoryOutputStream();

                ICipher keyCipher = cipherBuilder.BuildCipher(mOut);

                keyCipher.Stream.Write(cipherText, offset, length);

                keyCipher.Stream.Close();

                return new SimpleBlockResult(mOut.ToArray());
            }
        }
    }
}
