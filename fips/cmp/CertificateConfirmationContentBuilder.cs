using System.Collections;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Operators.Utilities;


namespace Org.BouncyCastle.Cmp
{
    public class CertificateConfirmationContentBuilder
    {

        private DefaultDigestAlgorithmIdentifierFinder digestAlgFinder;
        private ArrayList acceptedCerts = new ArrayList();
        private ArrayList acceptedReqIds = new ArrayList();

        public CertificateConfirmationContentBuilder() : this(new DefaultDigestAlgorithmIdentifierFinder())
        {

        }

        public CertificateConfirmationContentBuilder(DefaultDigestAlgorithmIdentifierFinder digestAlgFinder)
        {
            this.digestAlgFinder = digestAlgFinder;
        }

        public CertificateConfirmationContentBuilder AddAcceptedCertificate(X509Certificate certHolder,
            BigInteger certReqId)
        {
            acceptedCerts.Add(certHolder);
            acceptedReqIds.Add(certReqId);
            return this;
        }

        public CertificateConfirmationContent Build()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            for (int i = 0; i != acceptedCerts.Count; i++)
            {
                X509Certificate cert = (X509Certificate)acceptedCerts[i];
                BigInteger reqId = (BigInteger)acceptedReqIds[i];

                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.GetAlgorithmOid(cert.SigAlgName));

                AlgorithmIdentifier digAlg = digestAlgFinder.Find(algorithmIdentifier);
                if (digAlg == null)
                {
                    throw new CmpException("cannot find algorithm for digest from signature");
                }

                PkixDigestFactory digFact = new PkixDigestFactory(digAlg);
                IStreamCalculator<IBlockResult> calculator = digFact.CreateCalculator();

                var data = cert.GetEncoded();
                calculator.Stream.Write(data, 0, data.Length);
                var result = calculator.GetResult();
                byte[] dig = result.Collect();

                v.Add(new CertStatus(dig, reqId));
            }

            return new CertificateConfirmationContent(CertConfirmContent.GetInstance(new DerSequence(v)),
                digestAlgFinder);
        }
    }
}
