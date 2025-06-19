using System;

namespace Org.BouncyCastle.Tls.Core
{
    internal sealed class KeyUsage
    {
        internal static Asn1.X509.KeyUsage FromExtensions(Asn1.X509.X509Extensions extensions)
        {
            return Asn1.X509.KeyUsage.GetInstance(
                X509Extensions.GetExtensionParsedValue(extensions, Asn1.X509.X509Extensions.KeyUsage));
        }
    }
}
