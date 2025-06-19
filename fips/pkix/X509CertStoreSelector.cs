using System;
using System.Collections;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Pkix
{
    public class X509CertStoreSelector:IClonableSelector<X509Certificate>
    {

        private byte[] authorityKeyIdentifier;
        private int basicConstraints = -1;
        private X509Certificate certificate;
        private DateTimeObject certificateValid;
        private ISet extendedKeyUsage;
        private bool ignoreX509NameOrdering;
        private X500Name issuer;
        private bool[] keyUsage;
        private ISet policy;
        private DateTimeObject privateKeyValid;
        private BigInteger serialNumber;
        private X500Name subject;
        private byte[] subjectKeyIdentifier;
        private SubjectPublicKeyInfo subjectPublicKey;
        private DerObjectIdentifier subjectPublicKeyAlgID;

        public X509CertStoreSelector()
        {
        }

        public X509CertStoreSelector(
            ISelector<X509Certificate> src)
        {

            X509CertStoreSelector x509CertStoreSelector = src as X509CertStoreSelector;
            if (x509CertStoreSelector == null)
            {
                throw new ArgumentException("src is not X509CertStoreSelector");
            }


            this.authorityKeyIdentifier = x509CertStoreSelector.AuthorityKeyIdentifier;
            this.basicConstraints = x509CertStoreSelector.BasicConstraints;
            this.certificate = x509CertStoreSelector.Certificate;
            this.certificateValid = x509CertStoreSelector.CertificateValid;
            this.extendedKeyUsage = x509CertStoreSelector.ExtendedKeyUsage;
            this.ignoreX509NameOrdering = x509CertStoreSelector.IgnoreX509NameOrdering;
            this.issuer = x509CertStoreSelector.Issuer;
            this.keyUsage = x509CertStoreSelector.KeyUsage;
            this.policy = x509CertStoreSelector.Policy;
            this.privateKeyValid = x509CertStoreSelector.PrivateKeyValid;
            this.serialNumber = x509CertStoreSelector.SerialNumber;
            this.subject = x509CertStoreSelector.Subject;
            this.subjectKeyIdentifier = x509CertStoreSelector.SubjectKeyIdentifier;
            this.subjectPublicKey = x509CertStoreSelector.SubjectPublicKey;
            this.subjectPublicKeyAlgID = x509CertStoreSelector.SubjectPublicKeyAlgID;
        }

        public ISelector<X509Certificate> Clone()
        {
            return new X509CertStoreSelector(this);
        }


        public byte[] AuthorityKeyIdentifier
        {
            get { return Arrays.Clone(authorityKeyIdentifier); }
            set { authorityKeyIdentifier = Arrays.Clone(value); }
        }

        public int BasicConstraints
        {
            get { return basicConstraints; }
            set
            {
                if (value < -2)
                    throw new ArgumentException("value can't be less than -2", "value");

                basicConstraints = value;
            }
        }

        public X509Certificate Certificate
        {
            get { return certificate; }
            set { this.certificate = value; }
        }

        public DateTimeObject CertificateValid
        {
            get { return certificateValid; }
            set { certificateValid = value; }
        }

        public ISet ExtendedKeyUsage
        {
            get { return CopySet(extendedKeyUsage); }
            set { extendedKeyUsage = CopySet(value); }
        }

        public bool IgnoreX509NameOrdering
        {
            get { return ignoreX509NameOrdering; }
            set { this.ignoreX509NameOrdering = value; }
        }

        public X500Name Issuer
        {
            get { return issuer; }
            set { issuer = value; }
        }

        [Obsolete("Avoid working with X509Name objects in string form")]
        public string IssuerAsString
        {
            get { return issuer != null ? issuer.ToString() : null; }
        }

        public bool[] KeyUsage
        {
            get { return CopyBoolArray(keyUsage); }
            set { keyUsage = CopyBoolArray(value); }
        }

        /// <summary>
        /// An <code>ISet</code> of <code>DerObjectIdentifier</code> objects.
        /// </summary>
        public ISet Policy
        {
            get { return CopySet(policy); }
            set { policy = CopySet(value); }
        }

        public DateTimeObject PrivateKeyValid
        {
            get { return privateKeyValid; }
            set { privateKeyValid = value; }
        }

        public BigInteger SerialNumber
        {
            get { return serialNumber; }
            set { serialNumber = value; }
        }

        public X500Name Subject
        {
            get { return subject; }
            set { subject = value; }
        }

        [Obsolete("Avoid working with X509Name objects in string form")]
        public string SubjectAsString
        {
            get { return subject != null ? subject.ToString() : null; }
        }

        public byte[] SubjectKeyIdentifier
        {
            get { return Arrays.Clone(subjectKeyIdentifier); }
            set { subjectKeyIdentifier = Arrays.Clone(value); }
        }

        public SubjectPublicKeyInfo SubjectPublicKey
        {
            get { return subjectPublicKey; }
            set { subjectPublicKey = value; }
        }

        public DerObjectIdentifier SubjectPublicKeyAlgID
        {
            get { return subjectPublicKeyAlgID; }
            set { subjectPublicKeyAlgID = value; }
        
        }




        public virtual bool Match(X509Certificate c)
        {
                  
            if (c == null)
                return false;

            if (!MatchExtension(authorityKeyIdentifier, c, X509Extensions.AuthorityKeyIdentifier))
                return false;

            if (basicConstraints != -1)
            {
                int bc = c.GetBasicConstraints();

                if (basicConstraints == -2)
                {
                    if (bc != -1)
                        return false;
                }
                else
                {
                    if (bc < basicConstraints)
                        return false;
                }
            }

            if (certificate != null && !certificate.Equals(c))
                return false;

            if (certificateValid != null && !c.IsValid(certificateValid.Value))
                return false;

            if (extendedKeyUsage != null)
            {
                IList eku = c.GetExtendedKeyUsage();

                // Note: if no extended key usage set, all key purposes are implicitly allowed

                if (eku != null)
                {
                    foreach (DerObjectIdentifier oid in extendedKeyUsage)
                    {
                        if (!eku.Contains(oid))
                            return false;
                    }
                }
            }

            if (issuer != null && ! PkixCertFunctions.Equivalent(issuer, c.IssuerDN, !ignoreX509NameOrdering))
                return false;

            if (keyUsage != null)
            {
                bool[] ku = c.GetKeyUsage();

                // Note: if no key usage set, all key purposes are implicitly allowed

                if (ku != null)
                {
                    for (int i = 0; i < 9; ++i)
                    {
                        if (keyUsage[i] && !ku[i])
                            return false;
                    }
                }
            }

            if (policy != null)
            {
                byte[] extVal = c.GetExtensionValue(X509Extensions.CertificatePolicies);
               // Asn1OctetString extVal = c.GetExtensionValue(X509Extensions.CertificatePolicies);
                if (extVal == null)
                    return false;


                Asn1Sequence certPolicies = Asn1Sequence.GetInstance(extVal);

                //Asn1Sequence certPolicies = Asn1Sequence.GetInstance(
                //    X509ExtensionUtilities.FromExtensionValue(extVal));

                if (policy.Count < 1 && certPolicies.Count < 1)
                    return false;

                bool found = false;
                foreach (PolicyInformation pi in certPolicies)
                {
                    if (policy.Contains(pi.PolicyIdentifier))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    return false;
            }

            if (privateKeyValid != null)
            {
                // Asn1OctetString extVal = c.GetExtensionValue(X509Extensions.PrivateKeyUsagePeriod);
                byte[] extVal = c.GetExtensionValue(X509Extensions.PrivateKeyUsagePeriod);

                if (extVal == null)
                    return false;

                PrivateKeyUsagePeriod pkup = PrivateKeyUsagePeriod.GetInstance(
                    Asn1Sequence.FromByteArray(extVal));

                //PrivateKeyUsagePeriod pkup = PrivateKeyUsagePeriod.GetInstance(
                //    X509ExtensionUtilities.FromExtensionValue(extVal));

                DateTime dt = privateKeyValid.Value;
                DateTime notAfter = pkup.NotAfter.ToDateTime();
                DateTime notBefore = pkup.NotBefore.ToDateTime();

                if (dt.CompareTo(notAfter) > 0 || dt.CompareTo(notBefore) < 0)
                    return false;
            }

            if (serialNumber != null && !serialNumber.Equals(c.SerialNumber))
                return false;

            if (subject != null && !PkixCertFunctions.Equivalent(subject, c.SubjectDN, !ignoreX509NameOrdering))
                return false;

            if (!MatchExtension(subjectKeyIdentifier, c, X509Extensions.SubjectKeyIdentifier))
                return false;

            if (subjectPublicKey != null && !subjectPublicKey.Equals(GetSubjectPublicKey(c)))
                return false;

            if (subjectPublicKeyAlgID != null
                && !subjectPublicKeyAlgID.Equals(GetSubjectPublicKey(c).AlgorithmID))
                return false;

            return true;
        }

        internal static bool IssuersMatch(
            X500Name a,
            X500Name b)
        {
            return a == null ? b == null : PkixCertFunctions.Equivalent(a, b, true);
        }

        private static bool[] CopyBoolArray(
            bool[] b)
        {
            return b == null ? null : (bool[])b.Clone();
        }

        private static ISet CopySet(
            ISet s)
        {
            return s == null ? null : new HashSet(s);
        }

        private static SubjectPublicKeyInfo GetSubjectPublicKey(
            X509Certificate c)
        {
            return SubjectPublicKeyInfo.GetInstance(c.GetPublicKey().GetEncoded());                       
           // return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(c.GetPublicKey());
        }

        private static bool MatchExtension(
            byte[] b,
            X509Certificate c,
            DerObjectIdentifier oid)
        {
            if (b == null)
                return true;

           // Asn1OctetString extVal =    c.GetExtensionValue(oid);
            byte[] extVal = c.GetExtensionValue(oid);


            if (extVal == null)
                return false;

            return Arrays.AreEqual(b, extVal);
        }

       
    }
}
