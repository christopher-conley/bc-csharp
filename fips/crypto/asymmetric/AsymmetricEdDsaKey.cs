using System;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    /// <summary>
    /// Base class for Edwards Curve (EdDSA) keys.
    /// </summary>
	public abstract class AsymmetricEdDsaKey
        : IAsymmetricKey
	{
		private readonly bool approvedModeOnly;
		private readonly Algorithm algorithm;

		internal AsymmetricEdDsaKey(Algorithm algorithm)
		{
			this.approvedModeOnly = CryptoServicesRegistrar.IsInApprovedOnlyMode();
			this.algorithm = algorithm;
		}

		/// <summary>
		/// Return the algorithm this Elliptic Curve key is for.
		/// </summary>
		/// <value>The key's algorithm.</value>
		public Algorithm Algorithm
		{
            get { return CheckAccess().algorithm; }
		}

        /// <summary>
        /// Return an ASN.1 encoded representation of the implementing key.
        /// </summary>
        /// <returns>An encoded representation of the key.</returns>
        public abstract byte[] GetEncoded();

        private AsymmetricEdDsaKey CheckAccess()
        {
            if (this is AsymmetricEdDsaPrivateKey)
            {
                CheckApprovedOnlyModeStatus();
            }

            return this;
        }

        internal void CheckApprovedOnlyModeStatus()
		{
			if (approvedModeOnly != CryptoServicesRegistrar.IsInApprovedOnlyMode())
			{
				throw new CryptoUnapprovedOperationError("No access to key in current thread.");
			}
		}
	}
}

