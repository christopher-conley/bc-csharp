using System;

using Org.BouncyCastle.Crypto.Internal.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Internal.Generators
{
    internal class Ed25519KeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom random;

        public virtual void Init(KeyGenerationParameters parameters)
        {
            this.random = parameters.Random;
        }

        public virtual AsymmetricCipherKeyPair GenerateKeyPair()
        {
            Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(random);
            Ed25519PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }
    }
}
