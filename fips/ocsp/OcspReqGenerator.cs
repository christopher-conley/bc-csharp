using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Ocsp
{
	public class OcspReqGenerator
	{
		private List<RequestObject> list = new List<RequestObject>();
		private GeneralName		requestorName = null;
		private X509Extensions	requestExtensions = null;

		private class RequestObject
		{
			internal CertificateID certId;
			internal X509Extensions extensions;

			public RequestObject(
				CertificateID	certId,
				X509Extensions	extensions)
			{
				this.certId = certId;
				this.extensions = extensions;
			}

			public Request ToRequest()
			{
				return new Request(certId.ToAsn1Object(), extensions);
			}
		}

		/**
		 * Add a request for the given CertificateID.
		 *
		 * @param certId certificate ID of interest
		 */
		public void AddRequest(
			CertificateID certId)
		{
			list.Add(new RequestObject(certId, null));
		}

		/**
		 * Add a request with extensions
		 *
		 * @param certId certificate ID of interest
		 * @param singleRequestExtensions the extensions to attach to the request
		 */
		public void AddRequest(
			CertificateID   certId,
			X509Extensions  singleRequestExtensions)
		{
			list.Add(new RequestObject(certId, singleRequestExtensions));
		}

		/**
		* Set the requestor name to the passed in X509Principal
		*
		* @param requestorName a X509Principal representing the requestor name.
		*/
		public void SetRequestorName(
		    X500Name requestorName)
		{
		    try
		    {
		        this.requestorName = new GeneralName(GeneralName.DirectoryName, requestorName);
		    }
		    catch (Exception e)
		    {
		        throw new ArgumentException("cannot encode principal", e);
		    }
		}

		public void SetRequestorName(
			GeneralName requestorName)
		{
			this.requestorName = requestorName;
		}

		public void SetRequestExtensions(
			X509Extensions requestExtensions)
		{
			this.requestExtensions = requestExtensions;
		}

		private OcspReq GenerateRequest(
            ISignatureFactory<AlgorithmIdentifier> signatureFactory,
			X509Certificate[]		               chain)
		{
			Asn1EncodableVector requests = new Asn1EncodableVector();

			foreach (RequestObject reqObj in list)
			{
				try
				{
					requests.Add(reqObj.ToRequest());
				}
				catch (Exception e)
				{
					throw new OcspException("exception creating Request", e);
				}
			}

			TbsRequest tbsReq = new TbsRequest(requestorName, new DerSequence(requests), requestExtensions);

			Signature signature = null;

			if (signatureFactory != null)
			{
				if (requestorName == null)
				{
					throw new OcspException("requestorName must be specified if request is signed.");
				}

				DerBitString bitSig = null;

				try
				{
					byte[] encoded = tbsReq.GetEncoded();

                    IStreamCalculator<IBlockResult> streamCalculator = signatureFactory.CreateCalculator();

                    streamCalculator.Stream.Write(encoded, 0, encoded.Length);

                    Platform.Dispose(streamCalculator.Stream);

                    bitSig = new DerBitString(streamCalculator.GetResult().Collect());
				}
				catch (Exception e)
				{
					throw new OcspException("exception processing TBSRequest: " + e, e);
				}

				AlgorithmIdentifier sigAlgId = signatureFactory.AlgorithmDetails;

				if (chain != null && chain.Length > 0)
				{
					Asn1EncodableVector v = new Asn1EncodableVector();
					try
					{
						for (int i = 0; i != chain.Length; i++)
						{
							v.Add(chain[i].CertificateStructure);
						}
					}
					catch (IOException e)
					{
						throw new OcspException("error processing certs", e);
					}
					catch (CertificateEncodingException e)
					{
						throw new OcspException("error encoding certs", e);
					}

					signature = new Signature(sigAlgId, bitSig, new DerSequence(v));
				}
				else
				{
					signature = new Signature(sigAlgId, bitSig);
				}
			}

			return new OcspReq(new OcspRequest(tbsReq, signature));
		}

		/**
		 * Generate an unsigned request
		 *
		 * @return the OcspReq
		 * @throws OcspException
		 */
		public OcspReq Generate()
		{
			return GenerateRequest(null, null);
		}

		public OcspReq Generate(
			ISignatureFactory<AlgorithmIdentifier> signatureFactory,
			X509Certificate[]		               chain)
		{
			return GenerateRequest(signatureFactory, chain);
		}

		/**
		 * Return an IEnumerable of the signature names supported by the generator.
		 *
		 * @return an IEnumerable containing recognised names.
		 */
		public IEnumerable<string> SignatureAlgNames
		{
			get { return OcspUtilities.AlgNames; }
		}
	}
}
