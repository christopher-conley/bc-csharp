using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X500.Style;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkix
{
    /**
	 * The <i>Service Provider Interface</i> (<b>SPI</b>)
	 * for the {@link CertPathValidator CertPathValidator} class. All
	 * <code>CertPathValidator</code> implementations must include a class (the
	 * SPI class) that extends this class (<code>CertPathValidatorSpi</code>)
	 * and implements all of its methods. In general, instances of this class
	 * should only be accessed through the <code>CertPathValidator</code> class.
	 * For details, see the Java Cryptography Architecture.<br />
	 * <br />
	 * <b>Concurrent Access</b><br />
	 * <br />
	 * Instances of this class need not be protected against concurrent
	 * access from multiple threads. Threads that need to access a single
	 * <code>CertPathValidatorSpi</code> instance concurrently should synchronize
	 * amongst themselves and provide the necessary locking before calling the
	 * wrapping <code>CertPathValidator</code> object.<br />
	 * <br />
	 * However, implementations of <code>CertPathValidatorSpi</code> may still
	 * encounter concurrency issues, since multiple threads each
	 * manipulating a different <code>CertPathValidatorSpi</code> instance need not
	 * synchronize.
	 */
    /// <summary>
    /// CertPathValidatorSpi implementation for X.509 Certificate validation a la RFC
    /// 3280.
    /// </summary>
    public class PkixCertPathValidator
    {
        public virtual PkixCertPathValidatorResult Validate(
            PkixCertPath certPath,
            PkixParameters paramsPkix)
        {
            if (paramsPkix.GetTrustAnchors() == null)
            {
                throw new ArgumentException(
                    "trustAnchors is null, this is not allowed for certification path validation.",
                    "parameters");
            }

            //
            // 6.1.1 - inputs
            //

            //
            // (a)
            //
            IList<X509Certificate> certs = certPath.Certificates;
            int n = certs.Count;

            if (certs.Count == 0)
                throw new PkixCertPathValidatorException("Certification path is empty.", null, certPath, 0);

            //
            // (b)
            //
            // DateTime validDate = PkixCertPathValidatorUtilities.GetValidDate(paramsPkix);

            //
            // (c)
            //
            ISet<String> userInitialPolicySet = paramsPkix.GetInitialPolicies();

            //
            // (d)
            //
            TrustAnchor trust;
            try
            {
                trust = PkixCertPathValidatorUtilities.FindTrustAnchor(
                    (X509Certificate)certs[certs.Count - 1],
                    paramsPkix.GetTrustAnchors());

                if (trust == null)
                    throw new PkixCertPathValidatorException("Trust anchor for certification path not found.", null, certPath, -1);

                CheckCertificate(trust.TrustedCert);
            }
            catch (Exception e)
            {
                throw new PkixCertPathValidatorException(e.Message, e.InnerException, certPath, certs.Count - 1);
            }

            //
            // (e), (f), (g) are part of the paramsPkix object.
            //
            IEnumerator<PkixCertPathChecker> certIter;
            int index = 0;
            int i;
            // Certificate for each interation of the validation loop
            // Signature information for each iteration of the validation loop
            //
            // 6.1.2 - setup
            //

            //
            // (a)
            //
            IList<PkixPolicyNode>[] policyNodes = new IList<PkixPolicyNode>[n + 1];
            for (int j = 0; j < policyNodes.Length; j++)
            {
                policyNodes[j] = new List<PkixPolicyNode>();
            }

            ISet policySet = new HashSet();

            policySet.Add(Rfc3280CertPathUtilities.ANY_POLICY);

            PkixPolicyNode validPolicyTree = new PkixPolicyNode(Platform.CreateArrayList<PkixPolicyNode>(), 0, policySet, null, new HashSet(),
                    Rfc3280CertPathUtilities.ANY_POLICY, false);

            policyNodes[0].Add(validPolicyTree);

            //
            // (b) and (c)
            //
            PkixNameConstraintValidator nameConstraintValidator = new PkixNameConstraintValidator();

            // (d)
            //
            int explicitPolicy;
            ISet acceptablePolicies = new HashSet();

            if (paramsPkix.IsExplicitPolicyRequired)
            {
                explicitPolicy = 0;
            }
            else
            {
                explicitPolicy = n + 1;
            }

            //
            // (e)
            //
            int inhibitAnyPolicy;

            if (paramsPkix.IsAnyPolicyInhibited)
            {
                inhibitAnyPolicy = 0;
            }
            else
            {
                inhibitAnyPolicy = n + 1;
            }
            
            //
            // (f)
            //
            int policyMapping;

            if (paramsPkix.IsPolicyMappingInhibited)
            {
                policyMapping = 0;
            }
            else
            {
                policyMapping = n + 1;
            }

            //
            // (g), (h), (i), (j)
            //
            IAsymmetricKey workingPublicKey;
            X500Name workingIssuerName;

            X509Certificate sign = trust.TrustedCert;
            try
            {
                if (sign != null)
                {
                    workingIssuerName = sign.SubjectDN;
                    workingPublicKey = sign.GetPublicKey();
                }
                else
                {
                    workingIssuerName = new X500Name(trust.CAName);
                    workingPublicKey = trust.CAPublicKey;
                }
            }
            catch (ArgumentException ex)
            {
                throw new PkixCertPathValidatorException("Subject of trust anchor could not be (re)encoded.", ex, certPath,
                        -1);
            }

            AlgorithmIdentifier workingAlgId = null;
            try
            {
                workingAlgId = PkixCertPathValidatorUtilities.GetAlgorithmIdentifier(workingPublicKey);
            }
            catch (PkixCertPathValidatorException e)
            {
                throw new PkixCertPathValidatorException(
                        "Algorithm identifier of public key of trust anchor could not be read.", e, certPath, -1);
            }

            //			DerObjectIdentifier workingPublicKeyAlgorithm = workingAlgId.Algorithm;
            //			Asn1Encodable workingPublicKeyParameters = workingAlgId.Parameters;

            //
            // (k)
            //
            int maxPathLength = n;

            //
            // 6.1.3
            //

            ISelector<X509Certificate> certConstraints = paramsPkix.GetTargetCertConstraints();
            if (certConstraints != null && !certConstraints.Match((X509Certificate)certs[0]))
            {
                throw new PkixCertPathValidatorException(
                    "Target certificate in certification path does not match targetConstraints.", null, certPath, 0);
            }

            //
            // initialize CertPathChecker's
            //
            ICollection<PkixCertPathChecker> pathCheckers = paramsPkix.GetCertPathCheckers();
            certIter = pathCheckers.GetEnumerator();

            while (certIter.MoveNext())
            {
                ((PkixCertPathChecker)certIter.Current).Init(false);
            }
            

            X509Certificate cert = null;

            for (index = certs.Count - 1; index >= 0; index--)
            {
                // try
                // {
                //
                // i as defined in the algorithm description
                //
                i = n - index;

                //
                // set certificate to be checked in this round
                // sign and workingPublicKey and workingIssuerName are set
                // at the end of the for loop and initialized the
                // first time from the TrustAnchor
                //
                cert = (X509Certificate)certs[index];

                try
                {
                    CheckCertificate(cert);
                }
                catch (Exception e)
                {
                    throw new PkixCertPathValidatorException(e.Message, e.InnerException, certPath, index);
                }

                //
                // 6.1.3
                //

                Rfc3280CertPathUtilities.ProcessCertA(certPath, paramsPkix, index, workingPublicKey,
                    workingIssuerName, sign);

                Rfc3280CertPathUtilities.ProcessCertBC(certPath, index, nameConstraintValidator);

                validPolicyTree = Rfc3280CertPathUtilities.ProcessCertD(certPath, index,
                    acceptablePolicies, validPolicyTree, policyNodes, inhibitAnyPolicy);

                validPolicyTree = Rfc3280CertPathUtilities.ProcessCertE(certPath, index, validPolicyTree);

                Rfc3280CertPathUtilities.ProcessCertF(certPath, index, validPolicyTree, explicitPolicy);

                //
                // 6.1.4
                //

                if (i != n)
                {
                    if (cert != null && cert.Version == 1)
                    {
                        // we've found the trust anchor at the top of the path, ignore and keep going
                        if ((i == 1) && cert.Equals(trust.TrustedCert))
                            continue;

                        throw new PkixCertPathValidatorException(
                            "Version 1 certificates can't be used as CA ones.", null, certPath, index);
                    }

                    Rfc3280CertPathUtilities.PrepareNextCertA(certPath, index);

                    validPolicyTree = Rfc3280CertPathUtilities.PrepareCertB(certPath, index, policyNodes,
                        validPolicyTree, policyMapping);

                    Rfc3280CertPathUtilities.PrepareNextCertG(certPath, index, nameConstraintValidator);

                    // (h)
                    explicitPolicy = Rfc3280CertPathUtilities.PrepareNextCertH1(certPath, index, explicitPolicy);
                    policyMapping = Rfc3280CertPathUtilities.PrepareNextCertH2(certPath, index, policyMapping);
                    inhibitAnyPolicy = Rfc3280CertPathUtilities.PrepareNextCertH3(certPath, index, inhibitAnyPolicy);

                    //
                    // (i)
                    //
                    explicitPolicy = Rfc3280CertPathUtilities.PrepareNextCertI1(certPath, index, explicitPolicy);
                    policyMapping = Rfc3280CertPathUtilities.PrepareNextCertI2(certPath, index, policyMapping);

                    // (j)
                    inhibitAnyPolicy = Rfc3280CertPathUtilities.PrepareNextCertJ(certPath, index, inhibitAnyPolicy);

                    // (k)
                    Rfc3280CertPathUtilities.PrepareNextCertK(certPath, index);

                    // (l)
                    maxPathLength = Rfc3280CertPathUtilities.PrepareNextCertL(certPath, index, maxPathLength);

                    // (m)
                    maxPathLength = Rfc3280CertPathUtilities.PrepareNextCertM(certPath, index, maxPathLength);

                    // (n)
                    Rfc3280CertPathUtilities.PrepareNextCertN(certPath, index);

                    ISet<DerObjectIdentifier> criticalExtensions1 = PkixCertFunctions.AsSet<DerObjectIdentifier>(
                        cert.GetCriticalExtensionOids(),
                        delegate(object o) { return DerObjectIdentifier.GetInstance(o); });

                    if (criticalExtensions1 != null)
                    {
                        criticalExtensions1 = new HashSet<DerObjectIdentifier>(criticalExtensions1);

                        // these extensions are handled by the algorithm
                        criticalExtensions1.Remove(X509Extensions.KeyUsage);
                        criticalExtensions1.Remove(X509Extensions.CertificatePolicies);
                        criticalExtensions1.Remove(X509Extensions.PolicyMappings);
                        criticalExtensions1.Remove(X509Extensions.InhibitAnyPolicy);
                        criticalExtensions1.Remove(X509Extensions.IssuingDistributionPoint);
                        criticalExtensions1.Remove(X509Extensions.DeltaCrlIndicator);
                        criticalExtensions1.Remove(X509Extensions.PolicyConstraints);
                        criticalExtensions1.Remove(X509Extensions.BasicConstraints);
                        criticalExtensions1.Remove(X509Extensions.SubjectAlternativeName);
                        criticalExtensions1.Remove(X509Extensions.NameConstraints);
                    }
                    else
                    {
                        criticalExtensions1 = new HashSet<DerObjectIdentifier>();
                    }

                    // (o)
                    Rfc3280CertPathUtilities.PrepareNextCertO(certPath, index, criticalExtensions1, pathCheckers);

                    // set signing certificate for next round
                    sign = cert;

                    // (c)
                    workingIssuerName = sign.SubjectDN;

                    // (d)
                    try
                    {
                        workingPublicKey = PkixCertPathValidatorUtilities.GetNextWorkingKey(certPath.Certificates, index);
                    }
                    catch (PkixCertPathValidatorException e)
                    {
                        throw new PkixCertPathValidatorException("Next working key could not be retrieved.", e, certPath, index);
                    }

                    workingAlgId = PkixCertPathValidatorUtilities.GetAlgorithmIdentifier(workingPublicKey);
                    // (f)
                    //                    workingPublicKeyAlgorithm = workingAlgId.Algorithm;
                    // (e)
                    //                    workingPublicKeyParameters = workingAlgId.Parameters;
                }
            }

            //
            // 6.1.5 Wrap-up procedure
            //

            explicitPolicy = Rfc3280CertPathUtilities.WrapupCertA(explicitPolicy, cert);

            explicitPolicy = Rfc3280CertPathUtilities.WrapupCertB(certPath, index + 1, explicitPolicy);

            //
            // (c) (d) and (e) are already done
            //

            //
            // (f)
            //
            ISet<DerObjectIdentifier> criticalExtensions = PkixCertFunctions.AsSet<DerObjectIdentifier>(
                cert.GetCriticalExtensionOids(),
                delegate(object o) {return DerObjectIdentifier.GetInstance(o); });

            if (criticalExtensions != null)
            {
                criticalExtensions = new HashSet<DerObjectIdentifier>(criticalExtensions);

                // Requires .Id
                // these extensions are handled by the algorithm
                criticalExtensions.Remove(X509Extensions.KeyUsage);
                criticalExtensions.Remove(X509Extensions.CertificatePolicies);
                criticalExtensions.Remove(X509Extensions.PolicyMappings);
                criticalExtensions.Remove(X509Extensions.InhibitAnyPolicy);
                criticalExtensions.Remove(X509Extensions.IssuingDistributionPoint);
                criticalExtensions.Remove(X509Extensions.DeltaCrlIndicator);
                criticalExtensions.Remove(X509Extensions.PolicyConstraints);
                criticalExtensions.Remove(X509Extensions.BasicConstraints);
                criticalExtensions.Remove(X509Extensions.SubjectAlternativeName);
                criticalExtensions.Remove(X509Extensions.NameConstraints);
                criticalExtensions.Remove(X509Extensions.CrlDistributionPoints);
                criticalExtensions.Remove(X509Extensions.ExtendedKeyUsage);
            }
            else
            {
                criticalExtensions = new HashSet<DerObjectIdentifier>();
            }

            Rfc3280CertPathUtilities.WrapupCertF(certPath, index + 1, pathCheckers, criticalExtensions);

            PkixPolicyNode intersection = Rfc3280CertPathUtilities.WrapupCertG(certPath, paramsPkix, userInitialPolicySet,
                    index + 1, policyNodes, validPolicyTree, acceptablePolicies);

            if ((explicitPolicy > 0) || (intersection != null))
            {
                return new PkixCertPathValidatorResult(trust, intersection, cert.GetPublicKey());
            }

            throw new PkixCertPathValidatorException("Path processing failed on policy.", null, certPath, index);
        }

        internal static void CheckCertificate(X509Certificate cert)
        {
            try
            {
                TbsCertificateStructure.GetInstance( cert.GetTbsCertificate());
            }
            catch (CertificateEncodingException e)
            {
                throw new Exception("unable to process TBSCertificate", e);
            }
        }
    }
}
