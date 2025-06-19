using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crmf
{
    internal class CrmfUtilities
    {
        /// <summary>
        /// Create an instance of OptionalValidity
        /// </summary>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <returns></returns>
        internal static OptionalValidity CreateOptionalValidity(Time notBefore, Time notAfter)
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

            return OptionalValidity.GetInstance(new DerSequence(v));
        }
    }
}