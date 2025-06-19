using System;

using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPublicKeyEdDsaService : IVerifierFactoryService
    {

    }

    /// <summary>
    /// Class for Edwards Curve EdDSA public keys.
    /// </summary>
    public class AsymmetricEdDsaPublicKey: AsymmetricEdDsaKey, IAsymmetricPublicKey, ICryptoServiceType<IPublicKeyEdDsaService>, IServiceProvider<IPublicKeyEdDsaService>
    {
		static readonly byte[] Ed448Prefix = Hex.Decode("3043300506032b6571033a00");
		static readonly byte[] Ed25519Prefix = Hex.Decode("302a300506032b6570032100");

		//private static readonly byte Ed448_type = 0x71;
		//private static readonly byte Ed25519_type = 0x70;

		private readonly byte[] keyData;
		private readonly int hashCode;

		public AsymmetricEdDsaPublicKey(Algorithm ecAlg, byte[] keyData): base(ecAlg)
		{
			this.keyData = KeyUtils.IsValidEdDSAPublicKey(Arrays.Clone(keyData));
			this.hashCode = CalculateHashCode();
		}

		/// <summary>
		/// Constructor from an algorithm and an encoding of a SubjectPublicKeyInfo object containing an EC public key.
		/// </summary>
		/// <param name="encoding">An encoding of a SubjectPublicKeyInfo object.</param>
		public AsymmetricEdDsaPublicKey(byte[] encoding)
            : this(SubjectPublicKeyInfo.GetInstance(encoding))
		{
		}

        /// <summary>
        /// Constructor from a SubjectPublicKeyInfo object containing an EdDSA public key.
        /// </summary>
        /// <param name="publicKeyInfo">A SubjectPublicKeyInfo object.</param>
        public AsymmetricEdDsaPublicKey(SubjectPublicKeyInfo publicKeyInfo): base((publicKeyInfo.AlgorithmID.Algorithm.Equals(EdECObjectIdentifiers.id_Ed448) ? EdEC.Algorithm.Ed448 : EdEC.Algorithm.Ed25519))
		{
			this.keyData = KeyUtils.IsValidEdDSAPublicKey(publicKeyInfo.PublicKeyData.GetBytes());
			this.hashCode = CalculateHashCode();
		}

		public byte[] GetPublicData()
		{
			return Arrays.Clone(keyData);
		}

		/// <summary>
		/// Return an ASN.1 encoded representation of the implementing key in a SubjectPublicKeyInfo structure.
		/// </summary>
		/// <returns>An encoded representation of the key.</returns>
		public override byte[] GetEncoded()
		{
			if (Algorithm.Equals(EdEC.Algorithm.Ed448))
			{
				byte[] encoding = new byte[Ed448Prefix.Length + keyData.Length];

				Array.Copy(Ed448Prefix, 0, encoding, 0, Ed448Prefix.Length);
				Array.Copy(keyData, 0, encoding, Ed448Prefix.Length, keyData.Length);

				return encoding;
			}
			else
			{
				byte[] encoding = new byte[Ed25519Prefix.Length + keyData.Length];

				Array.Copy(Ed25519Prefix, 0, encoding, 0, Ed25519Prefix.Length);
				Array.Copy(keyData, 0, encoding, Ed25519Prefix.Length, keyData.Length);

				return encoding;
			}
		}

		public override bool Equals(object o)
		{
			if (this == o)
			{
				return true;
			}

			if (!(o is AsymmetricEdDsaPublicKey))
			{
				return false;
			}

			AsymmetricEdDsaPublicKey other = (AsymmetricEdDsaPublicKey)o;

			return Arrays.AreEqual(this.keyData, other.keyData);
		}

		public override int GetHashCode()
		{
			return hashCode;
		}

		private int CalculateHashCode()
		{
			int result = Algorithm.GetHashCode();
			result = 31 * result + Arrays.GetHashCode(keyData);
			return result;
		}

		Func<IKey, IPublicKeyEdDsaService> IServiceProvider<IPublicKeyEdDsaService>.GetFunc(SecurityContext context)
        {
            return (key) => new PublicKeyEdDsaService(key);
        }

        private class PublicKeyEdDsaService : IPublicKeyEdDsaService
        {
            private readonly AsymmetricEdDsaPublicKey publicKey;

            public PublicKeyEdDsaService(IKey publicKey)
            {
                this.publicKey = (AsymmetricEdDsaPublicKey)publicKey;
            }

            public IVerifierFactory<A> CreateVerifierFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

				if (algorithmDetails is EdEC.ParametersWithContext)
				{
					return (IVerifierFactory<A>)new VerifierFactory<General.EdEC.ParametersWithContext>(algorithmDetails as General.EdEC.ParametersWithContext, new General.EdEC.SignerProvider(algorithmDetails as General.EdEC.ParametersWithContext, publicKey));
				}
				else
                {
					return (IVerifierFactory<A>)new VerifierFactory<General.EdEC.Parameters>(algorithmDetails as General.EdEC.Parameters, new General.EdEC.SignerProvider(algorithmDetails as General.EdEC.Parameters, publicKey));
				}
            }
        }
    }
}

