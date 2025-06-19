using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Tls.Core
{
    internal sealed class X509Extensions
    {
        internal static Asn1Encodable GetExtensionParsedValue(Asn1.X509.X509Extensions extensions,
            DerObjectIdentifier oid)
        {
            if (null == extensions)
                return null;

            Asn1.X509.X509Extension ext = extensions.GetExtension(oid);
            if (null == ext)
                return null;

            return ext.GetParsedValue();
        }
    }
}
