using System;
using System.Text;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkix
{
    public class PkixCertPathValidatorResult
    {
        private TrustAnchor trustAnchor;
        private PkixPolicyNode policyTree;
        private IAsymmetricKey subjectPublicKey;

        public PkixPolicyNode PolicyTree
        {
            get { return this.policyTree; }
        }

        public TrustAnchor TrustAnchor
        {
            get { return this.trustAnchor; }
        }

        public IAsymmetricKey SubjectPublicKey
        {
            get { return this.subjectPublicKey; }
        }

        public PkixCertPathValidatorResult(
            TrustAnchor trustAnchor,
            PkixPolicyNode policyTree,
            IAsymmetricKey subjectPublicKey)
        {
            if (subjectPublicKey == null)
            {
                throw new NullReferenceException("subjectPublicKey must be non-null");
            }
            if (trustAnchor == null)
            {
                throw new NullReferenceException("trustAnchor must be non-null");
            }

            this.trustAnchor = trustAnchor;
            this.policyTree = policyTree;
            this.subjectPublicKey = subjectPublicKey;
        }

        public object Clone()
        {
            return new PkixCertPathValidatorResult(this.TrustAnchor, this.PolicyTree, this.SubjectPublicKey);
        }

        public override String ToString()
        {
            StringBuilder sB = new StringBuilder();
            sB.Append("PKIXCertPathValidatorResult: [ \n");
            sB.Append("  Trust Anchor: ").Append(this.TrustAnchor).Append('\n');
            sB.Append("  Policy Tree: ").Append(this.PolicyTree).Append('\n');
            sB.Append("  Subject Public Key: ").Append(this.SubjectPublicKey).Append("\n]");
            return sB.ToString();
        }
    }
}
