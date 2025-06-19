using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkix
{
    public interface IExtension
    {
        /// <summary>
        /// Get all critical extension values, by oid
        /// </summary>
        /// <returns>IDictionary with string (OID) keys and Asn1OctetString values</returns>
        IDictionary<string,Asn1OctetString> GetCriticalExtensionOids();

        /// <summary>
        /// Get all non-critical extension values, by oid
        /// </summary>
        /// <returns>IDictionary with string (OID) keys and Asn1OctetString values</returns>
        ISet<String> GetNonCriticalExtensionOids();

        [Obsolete("Use version taking a DerObjectIdentifier instead")]
        Asn1OctetString GetExtensionValue(string oid);

        Asn1OctetString GetExtensionValue(DerObjectIdentifier oid);
    }
}
