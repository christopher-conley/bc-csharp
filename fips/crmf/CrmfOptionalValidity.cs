using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crmf
{
    internal class CrmfOptionalValidity : Asn1Encodable
    {

        private readonly Time notBefore;
        private readonly Time notAfter;


        public CrmfOptionalValidity(Time notBefore, Time notAfter)
        {
            this.notAfter = notAfter;
            this.notBefore = notBefore;
        }

        public CrmfOptionalValidity(Asn1Sequence seq)
        {
            foreach (Asn1TaggedObject tObj in seq)
            {
                if (tObj.TagNo == 0)
                {
                    notBefore = Time.GetInstance(tObj, true);
                }
                else
                {
                    notAfter = Time.GetInstance(tObj, true);
                }
            }
        }

        public static CrmfOptionalValidity GetInstance(object obj)
        {
            if (obj == null || obj is CrmfOptionalValidity)
            {
                return (CrmfOptionalValidity)obj;
            }

            if (obj is OptionalValidity)
            {
                return GetInstance(((CrmfOptionalValidity)obj).GetEncoded());
            }


            return new CrmfOptionalValidity(Asn1Sequence.GetInstance(obj));
        }

        public virtual Time NotBefore
        {
            get { return notBefore; }
        }

        public virtual Time NotAfter
        {
            get { return notAfter; }
        }

        public OptionalValidity AsOptionalValidity()
        {
            return OptionalValidity.GetInstance(this.GetEncoded());
        }


        /**
         * <pre>
         * OptionalValidity ::= SEQUENCE {
         *                        notBefore  [0] Time OPTIONAL,
         *                        notAfter   [1] Time OPTIONAL } --at least one MUST be present
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            if (notBefore != null)
            {
                v.Add(new DerTaggedObject(true, 0, notBefore));
            }

            if (notAfter != null)
            {
                v.Add(new DerTaggedObject(true, 1, notAfter));
            }

            return new DerSequence(v);
        }
    }

}