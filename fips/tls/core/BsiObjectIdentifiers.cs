using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Tls.Core
{
	internal sealed class BsiObjectIdentifiers
	{
		private BsiObjectIdentifiers()
		{
		}

        internal static readonly DerObjectIdentifier bsi_de = new DerObjectIdentifier("0.4.0.127.0.7");

        /* 0.4.0.127.0.7.1.1 */
        internal static readonly DerObjectIdentifier id_ecc = bsi_de.Branch("1.1");

        /* 0.4.0.127.0.7.1.1.4.1 */
        internal static readonly DerObjectIdentifier ecdsa_plain_signatures = id_ecc.Branch("4.1");

        /* 0.4.0.127.0.7.1.1.4.1.1 */
        internal static readonly DerObjectIdentifier ecdsa_plain_SHA1 = ecdsa_plain_signatures.Branch("1");

        /* 0.4.0.127.0.7.1.1.4.1.2 */
        internal static readonly DerObjectIdentifier ecdsa_plain_SHA224 = ecdsa_plain_signatures.Branch("2");

        /* 0.4.0.127.0.7.1.1.4.1.3 */
        internal static readonly DerObjectIdentifier ecdsa_plain_SHA256 = ecdsa_plain_signatures.Branch("3");

        /* 0.4.0.127.0.7.1.1.4.1.4 */
        internal static readonly DerObjectIdentifier ecdsa_plain_SHA384 = ecdsa_plain_signatures.Branch("4");

        /* 0.4.0.127.0.7.1.1.4.1.5 */
        internal static readonly DerObjectIdentifier ecdsa_plain_SHA512 = ecdsa_plain_signatures.Branch("5");
    }
}
