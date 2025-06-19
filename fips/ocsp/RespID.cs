using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Ocsp
{
	/**
	 * Carrier for a ResponderID.
	 */
	public class RespID
	{
		internal readonly ResponderID id;

		public RespID(
			ResponderID id)
		{
			this.id = id;
		}

		public RespID(
			X500Name name)
		{
	        this.id = new ResponderID(name);
		}

		public RespID(
			IAsymmetricPublicKey publicKey)
		{
			try
			{
                IStreamCalculator<IBlockResult> calculator = CryptoServicesRegistrar.CreateService(FipsShs.Sha1).CreateCalculator();
				byte[] encoding = publicKey.GetEncoded();
                Stream cOut = calculator.Stream;

                try
                {
                    cOut.Write(encoding, 0, encoding.Length);

                    Platform.Dispose(cOut);
                }
                catch (IOException e)
                {   // it's hard to imagine this happening, but yes it does!
                    throw new CertificateException("unable to calculate identifier: " + e.Message, e);
                }

                this.id = new ResponderID(new DerOctetString(calculator.GetResult().Collect()));
			}
			catch (Exception e)
			{
				throw new OcspException("problem creating ID: " + e, e);
			}
		}

		public ResponderID ToAsn1Object()
		{
			return id;
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			RespID other = obj as RespID;

			if (other == null)
				return false;

			return id.Equals(other.id);
		}

		public override int GetHashCode()
		{
			return id.GetHashCode();
		}
	}
}
