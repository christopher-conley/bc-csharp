using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Ocsp
{
	/// <remarks>
	/// <code>
	/// BasicOcspResponse ::= SEQUENCE {
	///		tbsResponseData		ResponseData,
	///		signatureAlgorithm	AlgorithmIdentifier,
	///		signature			BIT STRING,
	///		certs				[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
	/// }
	/// </code>
	/// </remarks>
	public class BasicOcspResp
		: X509ExtensionBase
	{
		private readonly BasicOcspResponse	resp;
		private readonly ResponseData		data;
//		private readonly X509Certificate[]	chain;

		public BasicOcspResp(
			BasicOcspResponse resp)
		{
			this.resp = resp;
			this.data = resp.TbsResponseData;
		}

		/// <returns>The DER encoding of the tbsResponseData field.</returns>
		/// <exception cref="OcspException">In the event of an encoding error.</exception>
		public byte[] GetTbsResponseData()
		{
			try
			{
				return data.GetDerEncoded();
			}
			catch (IOException e)
			{
				throw new OcspException("problem encoding tbsResponseData", e);
			}
		}

		public int Version
		{
            get { return data.Version.IntValueExact + 1; }
		}

		public RespID ResponderId
		{
			get { return new RespID(data.ResponderID); }
		}

		public DateTime ProducedAt
		{
			get { return data.ProducedAt.ToDateTime(); }
		}

		public SingleResp[] Responses
		{
			get
			{
				Asn1Sequence s = data.Responses;
				SingleResp[] rs = new SingleResp[s.Count];

				for (int i = 0; i != rs.Length; i++)
				{
					rs[i] = new SingleResp(SingleResponse.GetInstance(s[i]));
				}

				return rs;
			}
		}

		public X509Extensions ResponseExtensions
		{
			get { return data.ResponseExtensions; }
		}

		protected override X509Extensions Extensions
		{
			get { return ResponseExtensions; }
		}

		public string SignatureAlgName
		{
            get { return OcspUtilities.GetAlgorithmName(resp.SignatureAlgorithm.Algorithm); }
		}

		public string SignatureAlgOid
		{
            get { return resp.SignatureAlgorithm.Algorithm.Id; }
		}

		public byte[] GetSignature()
		{
			return resp.GetSignatureOctets();
		}

		private List<X509Certificate> GetCertList()
		{
			// load the certificates if we have any

			var result = new List<X509Certificate>();

			Asn1Sequence certs = resp.Certs;
			if (certs != null)
			{
				foreach (Asn1Encodable ae in certs)
				{
					if (ae != null && ae.ToAsn1Object() is Asn1Sequence s)
					{
						result.Add(new X509Certificate(X509CertificateStructure.GetInstance(s)));
					}
				}
			}

			return result;
		}

		public X509Certificate[] GetCerts()
		{
			return GetCertList().ToArray();
		}

		/// <returns>The certificates, if any, associated with the response.</returns>
		/// <exception cref="OcspException">In the event of an encoding error.</exception>
		public IStore<X509Certificate> GetCertificates()
		{
			return new StoreImpl<X509Certificate>(this.GetCertList());
		}

        /// <summary>
        /// Verify the responses's signature using a verifier created using the passed in verifier provider.
        /// </summary>
        /// <param name="verifierProvider">An appropriate provider for verifying the responses's signature.</param>
		/// <returns>true is the signature on the response verifies, false otherwise.</returns>
        /// <exception cref="Exception">If verifier provider is not appropriate, the response's algorithm is invalid.</exception>
        public virtual bool IsVerified(
            IVerifierFactoryProvider<AlgorithmIdentifier> verifierProvider)
        {
            return CheckSignature(verifierProvider.CreateVerifierFactory(resp.SignatureAlgorithm));
        }

        protected virtual bool CheckSignature(
            IVerifierFactory<AlgorithmIdentifier> verifier)
        {
            Asn1Encodable parameters = resp.SignatureAlgorithm.Parameters;

            IStreamCalculator<IVerifier> streamCalculator = verifier.CreateCalculator();

            byte[] b = data.GetDerEncoded();

            streamCalculator.Stream.Write(b, 0, b.Length);

            Platform.Dispose(streamCalculator.Stream);

            return streamCalculator.GetResult().IsVerified(this.GetSignature());
        }

		/// <returns>The ASN.1 encoded representation of this object.</returns>
		public byte[] GetEncoded()
		{
			return resp.GetEncoded();
		}

		public override bool Equals(
			object obj)
		{
			if (obj == this)
				return true;

			BasicOcspResp other = obj as BasicOcspResp;

			if (other == null)
				return false;

			return resp.Equals(other.resp);
		}

		public override int GetHashCode()
		{
			return resp.GetHashCode();
		}
	}
}
