using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.IsisMtt;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Asymmetric;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>
    /// Summary description for PkixCertPathValidatorUtilities.
    /// </summary>
    public class PkixCertPathValidatorUtilities
    {
        private static readonly PkixCrlUtilities CrlUtilities = new PkixCrlUtilities();

        internal static readonly string ANY_POLICY = "2.5.29.32.0";

        internal static readonly string CRL_NUMBER = X509Extensions.CrlNumber.Id;

        /// <summary>
        /// key usage bits
        /// </summary>
        internal static readonly int KEY_CERT_SIGN = 5;
        internal static readonly int CRL_SIGN = 6;

        internal static readonly string[] crlReasons = new string[]
        {
        "unspecified",
        "keyCompromise",
        "cACompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "unknown",
        "removeFromCRL",
        "privilegeWithdrawn",
        "aACompromise"
        };

        /// <summary>
        /// Search the given Set of TrustAnchor's for one that is the
        /// issuer of the given X509 certificate.
        /// </summary>
        /// <param name="cert">the X509 certificate</param>
        /// <param name="trustAnchors">a Set of TrustAnchor's</param>
        /// <returns>the <code>TrustAnchor</code> object if found or
        /// <code>null</code> if not.
        /// </returns>
        /// @exception
        internal static TrustAnchor FindTrustAnchor(
            X509Certificate cert,
            ISet<TrustAnchor> trustAnchors)
        {
            IEnumerator<TrustAnchor> iter = trustAnchors.GetEnumerator();
            TrustAnchor trust = null;
            IAsymmetricKey trustPublicKey = null;
            Exception invalidKeyEx = null;

            X509CertStoreSelector certSelectX509 = new X509CertStoreSelector();

            try
            {
                certSelectX509.Subject = GetIssuerPrincipal(cert);
            }
            catch (IOException ex)
            {
                throw new Exception("Cannot set subject search criteria for trust anchor.", ex);
            }

            while (iter.MoveNext() && trust == null)
            {
                trust = iter.Current;
                if (trust.TrustedCert != null)
                {
                    if (certSelectX509.Match(trust.TrustedCert))
                    {
                        trustPublicKey = trust.TrustedCert.GetPublicKey();
                    }
                    else
                    {
                        trust = null;
                    }
                }
                else if (trust.CAName != null && trust.CAPublicKey != null)
                {
                    try
                    {
                        X500Name certIssuer = GetIssuerPrincipal(cert);
                        X500Name caName = new X500Name(trust.CAName);

                        if (certIssuer.Equivalent(caName)) //, true))
                        {
                            trustPublicKey = trust.CAPublicKey;
                        }
                        else
                        {
                            trust = null;
                        }
                    }
                    catch (Exception) // TODO verify if an exception is even thrown.
                    {
                        trust = null;
                    }
                }
                else
                {
                    trust = null;
                }

                if (trustPublicKey != null)
                {
                    try
                    {                           
                        cert.Verify(new PkixVerifierFactoryProvider((IAsymmetricPublicKey)trustPublicKey));
                    }
                    catch (Exception ex)
                    {
                        invalidKeyEx = ex;
                        trust = null;
                    }
                }
            }

            if (trust == null && invalidKeyEx != null)
            {
                throw new Exception("TrustAnchor found but certificate validation failed.", invalidKeyEx);
            }

            return trust;
        }

        internal static bool IsIssuerTrustAnchor(
            X509Certificate cert,
            ISet<TrustAnchor> trustAnchors)
        {
            try
            {
                return FindTrustAnchor(cert, trustAnchors) != null;
            }
            catch (Exception)
            {
                return false;
            }
        }

        internal static void AddAdditionalStoresFromAltNames(
            X509Certificate cert,
            PkixParameters pkixParams)
        {
            // if in the IssuerAltName extension an URI
            // is given, add an additinal X.509 store
            if (cert.GetIssuerAlternativeNames() != null)
            {
                IEnumerator it = cert.GetIssuerAlternativeNames().GetEnumerator();
                while (it.MoveNext())
                {
                    // look for URI
                    IList list = (IList)it.Current;
                    //if (list[0].Equals(new Integer(GeneralName.UniformResourceIdentifier)))
                    if (list[0].Equals(GeneralName.UniformResourceIdentifier))
                    {
                        // found
                        string temp = (string)list[1];
                        PkixCertPathValidatorUtilities.AddAdditionalStoreFromLocation(temp, pkixParams);
                    }
                }
            }
        }

        internal static DateTime GetValidDate(PkixParameters paramsPKIX)
        {
            DateTimeObject validDate = paramsPKIX.Date;

            if (validDate == null)
                return DateTime.UtcNow;

            return validDate.Value;
        }

        /// <summary>
        /// Returns the issuer of an attribute certificate or certificate.
        /// </summary>
        /// <param name="cert">The attribute certificate or certificate.</param>
        /// <returns>The issuer as <code>X500Principal</code>.</returns>
        internal static X500Name GetIssuerPrincipal(object cert)
        {
            if (cert is X509Certificate x509)
            {
                return x509.IssuerDN;
            }
            else
            {
                return ((X509V2AttributeCertificate)cert).Issuer.GetPrincipals()[0];
            }
        }

        internal static bool IsSelfIssued(
            X509Certificate cert)
        {
            return PkixCertFunctions.Equivalent(cert.SubjectDN, cert.IssuerDN, true);
        }

        internal static AlgorithmIdentifier GetAlgorithmIdentifier(
            IAsymmetricKey key)
        {
            try
            {
                SubjectPublicKeyInfo info = SubjectPublicKeyInfo.GetInstance(key.GetEncoded());
                return info.AlgorithmID;
            }
            catch (Exception e)
            {
                throw new PkixCertPathValidatorException("Subject public key cannot be decoded.", e);
            }
        }

        internal static bool IsAnyPolicy(
            ISet<String> policySet)
        {
            return policySet == null || policySet.Contains(ANY_POLICY) || policySet.Count == 0;
        }

        internal static void AddAdditionalStoreFromLocation(
            string location,
            PkixParameters pkixParams)
        {
            if (pkixParams.IsAdditionalLocationsEnabled)
            {
                try
                {
                    if (PkixCertFunctions.StartsWith(location, "ldap://"))
                    {
                        // ldap://directory.d-trust.net/CN=D-TRUST
                        // Qualified CA 2003 1:PN,O=D-Trust GmbH,C=DE
                        // skip "ldap://"
                        location = location.Substring(7);
                        // after first / baseDN starts
                        string url;//, baseDN;
                        int slashPos = location.IndexOf('/');
                        if (slashPos != -1)
                        {
                            url = "ldap://" + location.Substring(0, slashPos);
                            //							baseDN = location.Substring(slashPos);
                        }
                        else
                        {
                            url = "ldap://" + location;
                            //							baseDN = nsull;
                        }

                        throw Platform.CreateNotImplementedException("LDAP cert/CRL stores");

                        // use all purpose parameters
                        //X509LDAPCertStoreParameters ldapParams = new X509LDAPCertStoreParameters.Builder(
                        //                                url, baseDN).build();
                        //pkixParams.AddAdditionalStore(X509Store.getInstance(
                        //    "CERTIFICATE/LDAP", ldapParams));
                        //pkixParams.AddAdditionalStore(X509Store.getInstance(
                        //    "CRL/LDAP", ldapParams));
                        //pkixParams.AddAdditionalStore(X509Store.getInstance(
                        //    "ATTRIBUTECERTIFICATE/LDAP", ldapParams));
                        //pkixParams.AddAdditionalStore(X509Store.getInstance(
                        //    "CERTIFICATEPAIR/LDAP", ldapParams));
                    }
                }
                catch (Exception)
                {
                    // cannot happen
                    throw new Exception("Exception adding X.509 stores.");
                }
            }
        }

        private static BigInteger GetSerialNumber(
            object cert)
        {
            if (cert is X509Certificate x509)
            {
                return x509.SerialNumber;
            }
            else
            {
                return ((X509V2AttributeCertificate)cert).SerialNumber;
            }
        }

        //
        // policy checking
        //

        internal static ISet GetQualifierSet(Asn1Sequence qualifiers)
        {
            ISet pq = new HashSet();

            if (qualifiers == null)
            {
                return pq;
            }

            foreach (Asn1Encodable ae in qualifiers)
            {
                try
                {
                    //					pq.Add(PolicyQualifierInfo.GetInstance(Asn1Object.FromByteArray(ae.GetEncoded())));
                    pq.Add(PolicyQualifierInfo.GetInstance(ae.ToAsn1Object()));
                }
                catch (IOException ex)
                {
                    throw new PkixCertPathValidatorException("Policy qualifier info cannot be decoded.", ex);
                }
            }

            return pq;
        }

        internal static PkixPolicyNode RemovePolicyNode(
            PkixPolicyNode validPolicyTree,
            IList<PkixPolicyNode>[] policyNodes,
            PkixPolicyNode _node)
        {
            PkixPolicyNode _parent = (PkixPolicyNode)_node.Parent;

            if (validPolicyTree == null)
            {
                return null;
            }

            if (_parent == null)
            {
                for (int j = 0; j < policyNodes.Length; j++)
                {
                    policyNodes[j] = new List<PkixPolicyNode>();
                }

                return null;
            }
            else
            {
                _parent.RemoveChild(_node);
                RemovePolicyNodeRecurse(policyNodes, _node);

                return validPolicyTree;
            }
        }

        private static void RemovePolicyNodeRecurse(IList<PkixPolicyNode>[] policyNodes, PkixPolicyNode _node)
        {
            policyNodes[_node.Depth].Remove(_node);

            if (_node.HasChildren)
            {
                foreach (PkixPolicyNode _child in _node.Children)
                {
                    RemovePolicyNodeRecurse(policyNodes, _child);
                }
            }
        }

        internal static void PrepareNextCertB1(
            int i,
            IList[] policyNodes,
            string id_p,
            IDictionary m_idp,
            X509Certificate cert)
        {
            bool idp_found = false;
            IEnumerator nodes_i = policyNodes[i].GetEnumerator();
            while (nodes_i.MoveNext())
            {
                PkixPolicyNode node = (PkixPolicyNode)nodes_i.Current;
                if (node.ValidPolicy.Equals(id_p))
                {
                    idp_found = true;
                    node.ExpectedPolicies = (ISet)m_idp[id_p];
                    break;
                }
            }

            if (!idp_found)
            {
                nodes_i = policyNodes[i].GetEnumerator();
                while (nodes_i.MoveNext())
                {
                    PkixPolicyNode node = (PkixPolicyNode)nodes_i.Current;
                    if (ANY_POLICY.Equals(node.ValidPolicy))
                    {
                        ISet pq = null;

                        Asn1Sequence policies;
                        try
                        {
                            policies = DerSequence.GetInstance(cert.GetExtensionValue(X509Extensions.CertificatePolicies));
                        }
                        catch (Exception e)
                        {
                            throw new Exception("Certificate policies cannot be decoded.", e);
                        }

                        IEnumerator enm = policies.GetEnumerator();
                        while (enm.MoveNext())
                        {
                            PolicyInformation pinfo;
                            try
                            {
                                pinfo = PolicyInformation.GetInstance(enm.Current);
                            }
                            catch (Exception ex)
                            {
                                throw new Exception("Policy information cannot be decoded.", ex);
                            }

                            if (ANY_POLICY.Equals(pinfo.PolicyIdentifier.Id))
                            {
                                try
                                {
                                    pq = GetQualifierSet(pinfo.PolicyQualifiers);
                                }
                                catch (PkixCertPathValidatorException ex)
                                {
                                    throw new PkixCertPathValidatorException(
                                        "Policy qualifier info set could not be built.", ex);
                                }
                                break;
                            }
                        }
                        bool ci = false;
                        ISet critExtOids = cert.GetCriticalExtensionOids();
                        if (critExtOids != null)
                        {
                            ci = critExtOids.Contains(X509Extensions.CertificatePolicies);
                        }

                        PkixPolicyNode p_node = (PkixPolicyNode)node.Parent;
                        if (ANY_POLICY.Equals(p_node.ValidPolicy))
                        {
                            PkixPolicyNode c_node = new PkixPolicyNode(
                                Platform.CreateArrayList<PkixPolicyNode>(), i,
                                (ISet)m_idp[id_p],
                                p_node, pq, id_p, ci);
                            p_node.AddChild(c_node);
                            policyNodes[i].Add(c_node);
                        }
                        break;
                    }
                }
            }
        }

        internal static PkixPolicyNode PrepareNextCertB2(
            int i,
            IList<PkixPolicyNode>[] policyNodes,
            string id_p,
            PkixPolicyNode validPolicyTree)
        {
            int pos = 0;

            // Copy to avoid RemoveAt calls interfering with enumeration
            foreach (PkixPolicyNode node in new List<PkixPolicyNode>(policyNodes[i]))
            {
                if (node.ValidPolicy.Equals(id_p))
                {
                    PkixPolicyNode p_node = (PkixPolicyNode)node.Parent;
                    p_node.RemoveChild(node);

                    // Removal of element at current iterator position not supported in C#
                    //nodes_i.remove();
                    policyNodes[i].RemoveAt(pos);

                    for (int k = (i - 1); k >= 0; k--)
                    {
                        IList<PkixPolicyNode> nodes = policyNodes[k];
                        for (int l = 0; l < nodes.Count; l++)
                        {
                            PkixPolicyNode node2 = (PkixPolicyNode)nodes[l];
                            if (!node2.HasChildren)
                            {
                                validPolicyTree = RemovePolicyNode(validPolicyTree, policyNodes, node2);
                                if (validPolicyTree == null)
                                    break;
                            }
                        }
                    }
                }
                else
                {
                    ++pos;
                }
            }
            return validPolicyTree;
        }

        internal static void GetCertStatus(
            DateTime validDate,
            X509Crl crl,
            object cert,
            CertStatus certStatus)
        {
            X509Crl bcCRL;

            try
            {
                bcCRL = new X509Crl(CertificateList.GetInstance((Asn1Sequence)Asn1Sequence.FromByteArray(crl.GetEncoded())));
            }
            catch (Exception exception)
            {
                throw new Exception("Bouncy Castle X509Crl could not be created.", exception);
            }

            X509CrlEntry crl_entry = bcCRL.GetRevokedCertificate(GetSerialNumber(cert));

            if (crl_entry == null)
                return;

            X500Name issuer = GetIssuerPrincipal(cert);

            if (!PkixCertFunctions.Equivalent(issuer, crl_entry.CertificateIssuer, true)
                && !PkixCertFunctions.Equivalent(issuer, crl.IssuerDN, true))
            {
                return;
            }

            int reasonCodeValue = CrlReason.Unspecified;

            if (crl_entry.HasExtensions)
            {
                try
                {
                    Asn1Object extValue = Asn1Object.FromByteArray(
                        crl_entry.GetExtensionValue(X509Extensions.ReasonCode));
                    DerEnumerated reasonCode = DerEnumerated.GetInstance(extValue);
                    if (null != reasonCode)
                    {
                        reasonCodeValue = reasonCode.IntValueExact;
                    }
                }
                catch (Exception e)
                {
                    throw new Exception("Reason code CRL entry extension could not be decoded.", e);
                }
            }

            DateTime revocationDate = crl_entry.RevocationDate;
            if (validDate.Ticks < revocationDate.Ticks)
            {
                switch (reasonCodeValue)
                {
                case CrlReason.Unspecified:
                case CrlReason.KeyCompromise:
                case CrlReason.CACompromise:
                case CrlReason.AACompromise:
                    break;
                default:
                    return;
                }
            }

            // (i) or (j)
            certStatus.Status = reasonCodeValue;
            certStatus.RevocationDate = new DateTimeObject(revocationDate);
        }

        /**
        * Return the next working key inheriting DSA parameters if necessary.
        * <p>
        * This methods inherits DSA parameters from the indexed certificate or
        * previous certificates in the certificate chain to the returned
        * <code>PublicKey</code>. The list is searched upwards, meaning the end
        * certificate is at position 0 and previous certificates are following.
        * </p>
        * <p>
        * If the indexed certificate does not contain a DSA key this method simply
        * returns the public key. If the DSA key already contains DSA parameters
        * the key is also only returned.
        * </p>
        *
        * @param certs The certification path.
        * @param index The index of the certificate which contains the public key
        *            which should be extended with DSA parameters.
        * @return The public key of the certificate in list position
        *         <code>index</code> extended with DSA parameters if applicable.
        * @throws Exception if DSA parameters cannot be inherited.
        */
        internal static IAsymmetricKey GetNextWorkingKey(
            IList<X509Certificate> certs,
            int index)
        {
            //Only X509Certificate
            X509Certificate cert = (X509Certificate)certs[index];

            IAsymmetricKey pubKey = cert.GetPublicKey();

            if (!(pubKey is  AsymmetricDsaPublicKey))//   DsaPublicKeyParameters))
                return pubKey;

            AsymmetricDsaPublicKey dsaPubKey = (AsymmetricDsaPublicKey)pubKey;

            if (dsaPubKey.DomainParameters != null)
                return dsaPubKey;

            for (int i = index + 1; i < certs.Count; i++)
            {
                X509Certificate parentCert = (X509Certificate)certs[i];
                pubKey = parentCert.GetPublicKey();

                if (!(pubKey is AsymmetricDsaPublicKey))
                {
                    throw new PkixCertPathValidatorException(
                        "DSA parameters cannot be inherited from previous certificate.");
                }

                AsymmetricDsaPublicKey prevDSAPubKey = (AsymmetricDsaPublicKey)pubKey;

                if (prevDSAPubKey.DomainParameters == null)
                    continue;

                DsaDomainParameters dsaParams = prevDSAPubKey.DomainParameters;

                try
                {
                    return new AsymmetricDsaPublicKey(dsaPubKey.Algorithm, dsaParams,  dsaPubKey.Y);
                }
                catch (Exception exception)
                {
                    throw new Exception(exception.Message);
                }
            }

            throw new PkixCertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
        }

		internal static DateTime GetValidCertDateFromValidityModel(PkixParameters paramsPkix, PkixCertPath certPath,
			int index)
		{
			if (PkixParameters.ChainValidityModel != paramsPkix.ValidityModel || index <= 0)
			{
				// use given signing/encryption/... time (or current date)
				return GetValidDate(paramsPkix);
			}

			var issuedCert = certPath.Certificates[index - 1];

			if (index - 1 == 0)
			{
				// use time when cert was issued, if available
                DerGeneralizedTime dateOfCertgen = null;
				try
				{
                    byte[] extBytes = issuedCert.GetExtensionValue(IsisMttObjectIdentifiers.IdIsisMttATDateOfCertGen);
					if (extBytes != null)
					{
                        dateOfCertgen = DerGeneralizedTime.GetInstance(extBytes);
                    }
                }
				catch (ArgumentException e)
				{
					throw new Exception("Date of cert gen extension could not be read.", e);
				}
				if (dateOfCertgen != null)
				{
					try
					{
						return dateOfCertgen.ToDateTime();
					}
					catch (ArgumentException e)
					{
						throw new Exception("Date from date of cert gen extension could not be parsed.", e);
					}
				}
			}

			return issuedCert.NotBefore;
		}

        /// <summary>
        /// Return a Collection of all certificates or attribute certificates found
        /// in the X509Store's that are matching the certSelect criteriums.
        /// </summary>
        /// <param name="certSelect">a {@link Selector} object that will be used to select
        /// the certificates</param>
        /// <param name="certStores">a List containing only X509Store objects. These
        /// are used to search for certificates.</param>
        /// <returns>a Collection of all found <see cref="X509Certificate"/> objects.
        /// May be empty but never <code>null</code>.</returns>
        /// <exception cref="Exception"></exception>
        internal static ICollection<X509Certificate> FindCertificates(
            X509CertStoreSelector certSelect,
            ICollection<IStore<X509Certificate>> certStores)
        {
            ISet<X509Certificate> certs = new HashSet<X509Certificate>();

            foreach (IStore<X509Certificate> certStore in certStores)
            {
                try
                {
                    //certs.AddAll(certStore.GetMatches(certSelect));
                    foreach (X509Certificate c in certStore.GetMatches(certSelect))
                    {
                        certs.Add(c);
                    }
                }
                catch (Exception e)
                {
                    throw new Exception("Problem while picking certificates from X.509 store.", e);
                }
            }

            return certs;
        }

        /**
        * Add the CRL issuers from the cRLIssuer field of the distribution point or
        * from the certificate if not given to the issuer criterion of the
        * <code>selector</code>.
        * <p>
        * The <code>issuerPrincipals</code> are a collection with a single
        * <code>X500Principal</code> for <code>X509Certificate</code>s. For
        * {@link X509AttributeCertificate}s the issuer may contain more than one
        * <code>X500Principal</code>.
        * </p>
        *
        * @param dp The distribution point.
        * @param issuerPrincipals The issuers of the certificate or attribute
        *            certificate which contains the distribution point.
        * @param selector The CRL selector.
        * @param pkixParams The PKIX parameters containing the cert stores.
        * @throws Exception if an exception occurs while processing.
        * @throws ClassCastException if <code>issuerPrincipals</code> does not
        * contain only <code>X500Principal</code>s.
        */
        internal static void GetCrlIssuersFromDistributionPoint(
            DistributionPoint dp,
            ICollection issuerPrincipals,
            X509CrlStoreSelector selector,
            PkixParameters pkixParams)
        {
            IList<X500Name> issuers = new List<X500Name>();
            // indirect CRL
            if (dp.CrlIssuer != null)
            {
                GeneralName[] genNames = dp.CrlIssuer.GetNames();
                // look for a DN
                for (int j = 0; j < genNames.Length; j++)
                {
                    if (genNames[j].TagNo == GeneralName.DirectoryName)
                    {
                        try
                        {
                            issuers.Add(X500Name.GetInstance(genNames[j].Name.ToAsn1Object()));
                        }
                        catch (IOException e)
                        {
                            throw new Exception(
                                "CRL issuer information from distribution point cannot be decoded.",
                                e);
                        }
                    }
                }
            }
            else
            {
                /*
                    * certificate issuer is CRL issuer, distributionPoint field MUST be
                    * present.
                    */
                if (dp.DistributionPointName == null)
                {
                    throw new Exception(
                        "CRL issuer is omitted from distribution point but no distributionPoint field present.");
                }

                // add and check issuer principals
                for (IEnumerator it = issuerPrincipals.GetEnumerator(); it.MoveNext();)
                {
                    issuers.Add((X500Name)it.Current);
                }
            }
            // TODO: is not found although this should correctly add the rel name. selector of Sun is buggy here or PKI test case is invalid
            // distributionPoint
            //        if (dp.getDistributionPoint() != null)
            //        {
            //            // look for nameRelativeToCRLIssuer
            //            if (dp.getDistributionPoint().getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
            //            {
            //                // append fragment to issuer, only one
            //                // issuer can be there, if this is given
            //                if (issuers.size() != 1)
            //                {
            //                    throw new AnnotatedException(
            //                        "nameRelativeToCRLIssuer field is given but more than one CRL issuer is given.");
            //                }
            //                DEREncodable relName = dp.getDistributionPoint().getName();
            //                Iterator it = issuers.iterator();
            //                List issuersTemp = new ArrayList(issuers.size());
            //                while (it.hasNext())
            //                {
            //                    Enumeration e = null;
            //                    try
            //                    {
            //                        e = ASN1Sequence.getInstance(
            //                            new ASN1InputStream(((X500Principal) it.next())
            //                                .getEncoded()).readObject()).getObjects();
            //                    }
            //                    catch (IOException ex)
            //                    {
            //                        throw new AnnotatedException(
            //                            "Cannot decode CRL issuer information.", ex);
            //                    }
            //                    ASN1EncodableVector v = new ASN1EncodableVector();
            //                    while (e.hasMoreElements())
            //                    {
            //                        v.add((DEREncodable) e.nextElement());
            //                    }
            //                    v.add(relName);
            //                    issuersTemp.add(new X500Principal(new DERSequence(v)
            //                        .getDEREncoded()));
            //                }
            //                issuers.clear();
            //                issuers.addAll(issuersTemp);
            //            }
            //        }

            selector.Issuers = issuers;
        }

        /**
            * Fetches complete CRLs according to RFC 3280.
            *
            * @param dp The distribution point for which the complete CRL
            * @param cert The <code>X509Certificate</code> or
            *            {@link org.bouncycastle.x509.X509AttributeCertificate} for
            *            which the CRL should be searched.
            * @param currentDate The date for which the delta CRLs must be valid.
            * @param paramsPKIX The extended PKIX parameters.
            * @return A <code>Set</code> of <code>X509CRL</code>s with complete
            *         CRLs.
            * @throws Exception if an exception occurs while picking the CRLs
            *             or no CRLs are found.
            */
        internal static ISet<X509Crl> GetCompleteCrls(
            DistributionPoint dp,
            object cert,
            DateTime currentDate,
            PkixParameters paramsPKIX)
        {
            X509CrlStoreSelector crlselect = new X509CrlStoreSelector();
            try
            {
                ISet issuers = new HashSet();
                if (cert is X509V2AttributeCertificate attrCert)
                {
                    issuers.Add(attrCert.Issuer.GetPrincipals()[0]);
                }
                else
                {
                    issuers.Add(GetIssuerPrincipal(cert));
                }
                GetCrlIssuersFromDistributionPoint(dp, issuers, crlselect, paramsPKIX);
            }
            catch (Exception e)
            {
                throw new Exception("Could not get issuer information from distribution point.", e);
            }

            if (cert is X509Certificate x509)
            {
                crlselect.CertificateChecking = x509;
            }
            else if (cert is X509V2AttributeCertificate attrCert)
            {
                crlselect.AttrCertChecking = attrCert;
            }

            crlselect.CompleteCrlEnabled = true;
            ISet<X509Crl> crls = CrlUtilities.FindCrls(crlselect, paramsPKIX, currentDate);

            if (crls.Count == 0)
            {
                if (cert is X509V2AttributeCertificate aCert)
                {
                    throw new Exception("No CRLs found for issuer \"" + aCert.Issuer.GetPrincipals()[0] + "\"");
                }
                else
                {
                    X509Certificate xCert = (X509Certificate)cert;

                    throw new Exception("No CRLs found for issuer \"" + xCert.IssuerDN + "\"");
                }
            }

            return crls;
        }

        /**
            * Fetches delta CRLs according to RFC 3280 section 5.2.4.
            *
            * @param currentDate The date for which the delta CRLs must be valid.
            * @param paramsPKIX The extended PKIX parameters.
            * @param completeCRL The complete CRL the delta CRL is for.
            * @return A <code>Set</code> of <code>X509CRL</code>s with delta CRLs.
            * @throws Exception if an exception occurs while picking the delta
            *             CRLs.
            */
        internal static ISet<X509Crl> GetDeltaCrls(
            DateTime currentDate,
            PkixParameters paramsPKIX,
            X509Crl completeCRL)
        {
            X509CrlStoreSelector deltaSelect = new X509CrlStoreSelector();

            // 5.2.4 (a)
            try
            {
                deltaSelect.Issuers = new List<X500Name> { completeCRL.IssuerDN };
            }
            catch (IOException e)
            {
                throw new Exception("Cannot extract issuer from CRL.", e);
            }

            BigInteger completeCRLNumber = null;
            try
            {
                Asn1Object asn1Object =  PkixCertFunctions.NullSafeAsn1Object(completeCRL.GetExtensionValue(X509Extensions.CrlNumber));  //GetExtensionValue(completeCRL., X509Extensions.CrlNumber);
                if (asn1Object != null)
                {
                    completeCRLNumber = DerInteger.GetInstance(asn1Object).PositiveValue;
                }
            }
            catch (Exception e)
            {
                throw new Exception(
                    "CRL number extension could not be extracted from CRL.", e);
            }

            // 5.2.4 (b)
            byte[] idp = null;

            try
            {
                Asn1Object obj =  PkixCertFunctions.NullSafeAsn1Object(completeCRL.GetExtensionValue(X509Extensions.IssuingDistributionPoint)); //  GetExtensionValue(completeCRL, X509Extensions.IssuingDistributionPoint);
                if (obj != null)
                {
                    idp = obj.GetDerEncoded();
                }
            }
            catch (Exception e)
            {
                throw new Exception(
                    "Issuing distribution point extension value could not be read.",
                    e);
            }

            // 5.2.4 (d)

            deltaSelect.MinCrlNumber = completeCRLNumber?.Add(BigInteger.One);

            deltaSelect.IssuingDistributionPoint = idp;
            deltaSelect.IssuingDistributionPointEnabled = true;

            // 5.2.4 (c)
            deltaSelect.MaxBaseCrlNumber = completeCRLNumber;
            
            // find delta CRLs
            ISet<X509Crl> temp = CrlUtilities.FindCrls(deltaSelect, paramsPKIX, currentDate);

            ISet<X509Crl> result = new HashSet<X509Crl>();

            foreach (X509Crl crl in temp)
            {
                if (IsDeltaCrl(crl))
                {
                    result.Add(crl);
                }
            }

            return result;
        }

        private static bool IsDeltaCrl(X509Crl crl)
        {
            ISet critical = crl.GetCriticalExtensionOids();

            return critical.Contains(X509Extensions.DeltaCrlIndicator);
        }

        internal static ICollection FindCertificates(
            X509AttrCertStoreSelector certSelect,
            IList<IStore<X509V2AttributeCertificate>> certStores)
        {
            ISet certs = new HashSet();

            foreach (IStore<X509V2AttributeCertificate> certStore in certStores)
            {
                try
                {
                    //certs.AddAll(certStore.GetMatches(certSelect));
                    foreach (X509V2AttributeCertificate ac in certStore.GetMatches(certSelect))
                    {
                        certs.Add(ac);
                    }
                }
                catch (Exception e)
                {
                    throw new Exception(
                        "Problem while picking certificates from X.509 store.", e);
                }
            }

            return certs;
        }

        internal static void AddAdditionalStoresFromCrlDistributionPoint(
            CrlDistPoint crldp,
            PkixParameters pkixParams)
        {
            if (crldp != null)
            {
                DistributionPoint[] dps;
                try
                {
                    dps = crldp.GetDistributionPoints();
                }
                catch (Exception e)
                {
                    throw new Exception(
                        "Distribution points could not be read.", e);
                }
                for (int i = 0; i < dps.Length; i++)
                {
                    DistributionPointName dpn = dps[i].DistributionPointName;
                    // look for URIs in fullName
                    if (dpn != null)
                    {
                        if (dpn.PointType == DistributionPointName.FullName)
                        {
                            GeneralName[] genNames = GeneralNames.GetInstance(
                                dpn.Name).GetNames();
                            // look for an URI
                            for (int j = 0; j < genNames.Length; j++)
                            {
                                if (genNames[j].TagNo == GeneralName.UniformResourceIdentifier)
                                {
                                    string location = DerIA5String.GetInstance(
                                        genNames[j].Name).GetString();
                                    PkixCertPathValidatorUtilities.AddAdditionalStoreFromLocation(
                                        location, pkixParams);
                                }
                            }
                        }
                    }
                }
            }
        }

        internal static bool ProcessCertD1i(
            int index,
            IList<PkixPolicyNode>[] policyNodes,
            DerObjectIdentifier pOid,
            ISet pq)
        {
            IList<PkixPolicyNode> policyNodeVec = policyNodes[index - 1];

            for (int j = 0; j < policyNodeVec.Count; j++)
            {
                PkixPolicyNode node = policyNodeVec[j];
                ISet expectedPolicies = node.ExpectedPolicies;

                if (expectedPolicies.Contains(pOid.Id))
                {
                    ISet childExpectedPolicies = new HashSet { pOid.Id };

                    PkixPolicyNode child = new PkixPolicyNode(Platform.CreateArrayList<PkixPolicyNode>(),
                        index,
                        childExpectedPolicies,
                        node,
                        pq,
                        pOid.Id,
                        false);
                    node.AddChild(child);
                    policyNodes[index].Add(child);

                    return true;
                }
            }

            return false;
        }

        internal static void ProcessCertD1ii(
            int index,
            IList<PkixPolicyNode>[] policyNodes,
            DerObjectIdentifier _poid,
            ISet _pq)
        {
            IList<PkixPolicyNode> policyNodeVec = policyNodes[index - 1];

            for (int j = 0; j < policyNodeVec.Count; j++)
            {
                PkixPolicyNode _node = (PkixPolicyNode)policyNodeVec[j];

                if (ANY_POLICY.Equals(_node.ValidPolicy))
                {
                    ISet _childExpectedPolicies = new HashSet { _poid.Id };

                    PkixPolicyNode _child = new PkixPolicyNode(Platform.CreateArrayList<PkixPolicyNode>(),
                        index,
                        _childExpectedPolicies,
                        _node,
                        _pq,
                        _poid.Id,
                        false);
                    _node.AddChild(_child);
                    policyNodes[index].Add(_child);
                    return;
                }
            }
        }

        /**
        * Find the issuer certificates of a given certificate.
        *
        * @param cert
        *            The certificate for which an issuer should be found.
        * @param pkixParams
        * @return A <code>Collection</code> object containing the issuer
        *         <code>X509Certificate</code>s. Never <code>null</code>.
        *
        * @exception Exception
        *                if an error occurs.
        */
        internal static ICollection<X509Certificate> FindIssuerCerts(
            X509Certificate cert,
            PkixBuilderParameters pkixParams)
        {
           

            X509CertStoreSelector certSelect = new X509CertStoreSelector();
            ISet<X509Certificate> certs = new HashSet<X509Certificate>();
            try
            {
                certSelect.Subject = cert.IssuerDN;
            }
            catch (IOException ex)
            {
                throw new Exception(
                    "Subject criteria for certificate selector to find issuer certificate could not be set.", ex);
            }

            try
            {
                    
                foreach (IStore<X509Certificate> store in pkixParams.GetCertStores())
                {
                    PkixCertFunctions.Cpy(certs,
                        PkixCertPathValidatorUtilities.FindCertificates(certSelect, pkixParams.GetCertStores()));                      
                }                               

                //certs.Add(pkixParams.GetStores());//    PkixCertPathValidatorUtilities.FindCertificates(certSelect, pkixParams.GetStores()));

                //  certs.AddAll(PkixCertPathValidatorUtilities.FindCertificates(certSelect, pkixParams.GetAdditionalStores()));
            }
            catch (Exception e)
            {
                throw new Exception("Issuer certificate cannot be searched.", e);
            }

            return certs;
        }

        /// <summary>
        /// Extract the value of the given extension, if it exists.
        /// </summary>
        /// <param name="ext">The extension object.</param>
        /// <param name="oid">The object identifier to obtain.</param>
        /// <returns>Asn1Object</returns>
        /// <exception cref="Exception">if the extension cannot be read.</exception>
        internal static Asn1Object GetExtensionValue(
            X509Extensions ext,
            DerObjectIdentifier oid)
        {
            Asn1OctetString bytes = ext.GetExtension(oid).Value; //   GetExtensionValue(oid);

            if (bytes == null)
                return null;

            return Asn1Object.FromByteArray(bytes.GetOctets()); // X509ExtensionUtilities.FromExtensionValue(bytes);
        }
    }
}
