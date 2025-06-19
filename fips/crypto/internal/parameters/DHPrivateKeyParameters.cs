using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Internal.Parameters
{
    internal class DHPrivateKeyParameters
		: DHKeyParameters
    {
        private readonly BigInteger x;

		public DHPrivateKeyParameters(
            BigInteger			x,
            DHParameters	parameters)
			: base(true, parameters)
        {
			if (x == null)
				throw new ArgumentNullException("x");

			this.x = x;
        }

		public BigInteger X
        {
            get { return x; }
        }

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			DHPrivateKeyParameters other = obj as DHPrivateKeyParameters;

			if (other == null)
				return false;

			return Equals(other);
		}

		protected bool Equals(
			DHPrivateKeyParameters other)
		{
			return other.x.Equals(x) && base.Equals(other);
		}

		public override int GetHashCode()
		{
			return x.GetHashCode() ^ base.GetHashCode();
		}
    }
}
