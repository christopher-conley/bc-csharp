using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Ocsp
{
	public class CertificateID
	{
		public static readonly AlgorithmIdentifier HashSha1 = new AlgorithmIdentifier(new DerObjectIdentifier("1.3.14.3.2.26"), DerNull.Instance);

		private readonly CertID id;

		public CertificateID(
			CertID id)
		{
			if (id == null)
				throw new ArgumentNullException("id");

			this.id = id;
		}

		/**
		 * create from an issuer certificate and the serial number of the
		 * certificate it signed.
		 * @exception OcspException if any problems occur creating the id fields.
		 */
		public CertificateID(
			IDigestFactory<AlgorithmIdentifier>	hashFactory,
			X509Certificate	                    issuerCert,
			BigInteger	                        serialNumber)
		{
			this.id = CreateCertID(hashFactory, issuerCert, new DerInteger(serialNumber));
		}

		public string HashAlgOid
		{
            get { return id.HashAlgorithm.Algorithm.Id; }
		}

		public byte[] GetIssuerNameHash()
		{
			return id.IssuerNameHash.GetOctets();
		}

		public byte[] GetIssuerKeyHash()
		{
			return id.IssuerKeyHash.GetOctets();
		}

		/**
		 * return the serial number for the certificate associated
		 * with this request.
		 */
		public BigInteger SerialNumber
		{
			get { return id.SerialNumber.Value; }
		}

		public bool MatchesIssuer(
            IDigestFactoryProvider<AlgorithmIdentifier> hashFactoryProvider,
            X509Certificate	                            issuerCert)
		{
			return CreateCertID(hashFactoryProvider.CreateDigestFactory(id.HashAlgorithm), issuerCert, id.SerialNumber).Equals(id);
		}

        public bool MatchesIssuer(
			IDigestFactory<AlgorithmIdentifier> hashFactory,
			X509Certificate issuerCert)
        {
			if (!hashFactory.AlgorithmDetails.Equals(id.HashAlgorithm))
			{
				throw new ArgumentException("digest factory does not match required digest algorithm");
			}
            return CreateCertID(hashFactory, issuerCert, id.SerialNumber).Equals(id);
        }

        public CertID ToAsn1Object()
		{
			return id;
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			CertificateID other = obj as CertificateID;

			if (other == null)
				return false;

			return id.ToAsn1Object().Equals(other.id.ToAsn1Object());
		}

		public override int GetHashCode()
		{
			return id.ToAsn1Object().GetHashCode();
		}


		/**
		 * Create a new CertificateID for a new serial number derived from a previous one
		 * calculated for the same CA certificate.
		 *
		 * @param original the previously calculated CertificateID for the CA.
		 * @param newSerialNumber the serial number for the new certificate of interest.
		 *
		 * @return a new CertificateID for newSerialNumber
		 */
		public static CertificateID DeriveCertificateID(CertificateID original, BigInteger newSerialNumber)
		{
			return new CertificateID(new CertID(original.id.HashAlgorithm, original.id.IssuerNameHash,
				original.id.IssuerKeyHash, new DerInteger(newSerialNumber)));
		}

        private static CertID CreateCertID(
			IDigestFactory<AlgorithmIdentifier> hashAlgorithm,
			X509Certificate		issuerCert,
			DerInteger			serialNumber)
		{
			try
			{
				X500Name issuerName = issuerCert.SubjectDN;
				byte[] issuerNameHash = CalculateDigest(hashAlgorithm, issuerName.GetEncoded());

				IAsymmetricPublicKey issuerKey = issuerCert.GetPublicKey();
				byte[] issuerKeyHash = CalculateDigest(hashAlgorithm, issuerKey.GetEncoded());

				return new CertID(hashAlgorithm.AlgorithmDetails, new DerOctetString(issuerNameHash),
					new DerOctetString(issuerKeyHash), serialNumber);
			}
			catch (Exception e)
			{
				throw new OcspException("problem creating ID: " + e, e);
			}
		}

		private static byte[] CalculateDigest(IDigestFactory<AlgorithmIdentifier> digestFactory, byte[] data)
		{
            IStreamCalculator<IBlockResult> calculator = CryptoServicesRegistrar.CreateService(FipsShs.Sha1).CreateCalculator();
            Stream cOut = calculator.Stream;

            try
            {
                cOut.Write(data, 0, data.Length);

                Platform.Dispose(cOut);
            }
            catch (IOException e)
            {   // it's hard to imagine this happening, but yes it does!
                throw new CertificateException("unable to calculate identifier: " + e.Message, e);
            }

			return calculator.GetResult().Collect();
        }
	}
}
