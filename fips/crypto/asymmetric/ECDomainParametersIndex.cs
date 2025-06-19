using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Internal.EC;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
	public class ECDomainParametersIndex
	{
		/**
	     * Retrieve an EC based domain parameter by OID. A custom curve will be returned if one is available.
	     *
	     * @param paramOid object identifier for the domain parameters.
	     * @return the matching domain parameters if found, null otherwise.
	     */
		public static NamedECDomainParameters LookupDomainParameters(DerObjectIdentifier paramOid)
		{
			X9ECParameters rv = CustomNamedCurves.GetByOid(paramOid);

			if (rv == null)
			{
				rv = ECNamedCurveTable.GetByOid(paramOid);
			}

			if (rv != null)
			{
				return new NamedECDomainParameters(paramOid, rv.Curve, rv.G, rv.N, rv.H, rv.GetSeed());
			}

			return null;
		}

		/**
	     * Retrieve an EC based domain parameter by parameter ID. A custom curve will be returned if one is available.
	     *
	     * @param paramID identifier for the domain parameters.
	     * @return the matching domain parameters if found, null otherwise.
	     */
		public static NamedECDomainParameters LookupDomainParameters(IECDomainParametersID paramID)
		{
			string curveName = paramID.CurveName;
			X9ECParameters rv = CustomNamedCurves.GetByName(curveName);

			if (rv == null)
			{
				rv = ECNamedCurveTable.GetByName(curveName);
			}

			if (rv != null)
			{
				DerObjectIdentifier oid = ECNamedCurveTable.GetOid(curveName);
				if (oid != null)
				{
					return new NamedECDomainParameters(oid, rv.Curve, rv.G, rv.N, rv.H, rv.GetSeed());
				}
			}

			return null;
		}

		public static DerObjectIdentifier LookupOid(ECDomainParameters domainParameters)
		{
			foreach (string name in ECNamedCurveTable.Names)
            {
				X9ECParameters rv = ECNamedCurveTable.GetByName(name);

				if (rv != null && rv.N != null && rv.N.Equals(domainParameters.N))
                {
					return ECNamedCurveTable.GetOid(name);
                }
            }

			return null;
		}
	}
}
