


using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Utilities;


namespace Org.BouncyCastle.Cmp
{
    public class CertificateStatus
    {
      //  private DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
        private DefaultDigestAlgorithmIdentifierFinder digestAlgFinder;
        private CertStatus certStatus;

        public CertificateStatus(DefaultDigestAlgorithmIdentifierFinder digestAlgFinder, CertStatus certStatus)
        {
            this.digestAlgFinder = digestAlgFinder;
            this.certStatus = certStatus;
        }

         public PkiStatusInfo PkiStatusInfo
         {
             get { return certStatus.StatusInfo; }
         }

        public BigInteger CertRequestId
        {
            get { return certStatus.CertReqID.Value; }
        }

        public bool IsVerified(X509Certificate cert)
        {

            AlgorithmIdentifier digAlg = new AlgorithmIdentifier(Utils.GetAlgorithmOid(cert.SigAlgName));
            if (digAlg == null)
            {
                throw new CmpException("cannot find algorithm for digest from signature "+cert.SigAlgName);
            }

            PkixDigestFactory digFact = new PkixDigestFactory(digAlg);
            IStreamCalculator<IBlockResult> calculator = digFact.CreateCalculator();

            var data = cert.GetEncoded();
            calculator.Stream.Write(data, 0, data.Length);
            var result = calculator.GetResult();
            byte[] digest = result.Collect();

            //DigestSink digestSink = new DigestSink(DigestUtilities.GetDigest(digAlg.Algorithm));

            //digestSink.Write(cert.GetEncoded());

            //byte[] digest = new byte[digestSink.Digest.GetDigestSize()];
            //digestSink.Digest.DoFinal(digest, 0);
            return Arrays.ConstantTimeAreEqual(certStatus.CertHash.GetOctets(), digest);
        }
    }
}
