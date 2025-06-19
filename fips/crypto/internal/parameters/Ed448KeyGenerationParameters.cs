using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    internal class Ed448KeyGenerationParameters
        : KeyGenerationParameters
    {
        public Ed448KeyGenerationParameters(SecureRandom random)
            : base(random, 448)
        {
        }
    }
}
