using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.General;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Asymmetric
{
    public interface IPrivateKeyEdDsaService : ISignatureFactoryService
    {

    }

    public class AsymmetricEdDsaPrivateKey: AsymmetricEdDsaKey, IAsymmetricPrivateKey, ICryptoServiceType<IPrivateKeyEdDsaService>, IServiceProvider<IPrivateKeyEdDsaService>
    {
        private readonly byte[]     keyData;

        private readonly bool hasPublicKey;
        private readonly byte[] publicData;
        private readonly Asn1Set attributes;
        private readonly int hashCode;

        public AsymmetricEdDsaPrivateKey(Algorithm algorithm, byte[] keyData, byte[] publicData): base(algorithm)
        {
            this.keyData = Arrays.Clone(keyData);
            this.hashCode = CalculateHashCode();
            this.attributes = null;
            if (publicData == null)
            {
                this.hasPublicKey = false;
                this.publicData = ComputePublicData(algorithm, keyData);
            }
            else
            {
                this.hasPublicKey = true;
                this.publicData = Arrays.Clone(publicData);
            }
        }

        /**
         * Construct a key from an encoding of a PrivateKeyInfo.
         *
         * @param encoding the DER encoding of the key.
         */
        public AsymmetricEdDsaPrivateKey(byte[] encoding): this(PrivateKeyInfo.GetInstance(encoding))
        {
        
        }

    /**
     * Construct a key from a PrivateKeyInfo.
     *
     * @param keyInfo the PrivateKeyInfo containing the key.
     */
    public AsymmetricEdDsaPrivateKey(PrivateKeyInfo keyInfo): 
            base(EdECObjectIdentifiers.id_Ed448.Equals(keyInfo.PrivateKeyAlgorithm.Algorithm)
                    ? EdEC.Algorithm.Ed448 : EdEC.Algorithm.Ed25519)
        {

            Asn1Encodable keyOcts = keyInfo.ParsePrivateKey();
            keyData = Arrays.Clone(Asn1OctetString.GetInstance(keyOcts).GetOctets());

            if (keyInfo.HasPublicKey)
            {
                hasPublicKey = true;
                publicData = Arrays.Clone(keyInfo.PublicKeyData.GetOctets());
            }
            else
            {
                hasPublicKey = false;
                this.publicData = ComputePublicData(Algorithm, keyData);
            }

            if (EdECObjectIdentifiers.id_Ed448.Equals(keyInfo.PrivateKeyAlgorithm.Algorithm))
            {
                if (keyData.Length != EdEC.Ed448PrivateKeySize)
                {
                    throw new ArgumentException("raw key data incorrect size");
                }
            }
            else
            {
                if (keyData.Length != EdEC.Ed25519PrivateKeySize)
                {
                    throw new ArgumentException("raw key data incorrect size");
                }
            }

            this.attributes = keyInfo.Attributes;
            this.hashCode = CalculateHashCode();
        }

        public byte[] GetSecret()
        {
            CheckApprovedOnlyModeStatus();

            return Arrays.Clone(keyData);
        }

        public byte[] GetPublicData()
        {
            return Arrays.Clone(publicData);
        }

        public override byte[] GetEncoded()
        {
            CheckApprovedOnlyModeStatus();

            byte[] pubData = (hasPublicKey && !Properties.IsOverrideSet("org.bouncycastle.pkcs8.v1_info_only")) ? publicData : null;

            if (Algorithm.Equals(EdEC.Algorithm.Ed448))
            {
                return KeyUtils.GetEncodedPrivateKeyInfo(
                    new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), new DerOctetString(keyData), attributes, pubData);
            }
            else
            {
                return KeyUtils.GetEncodedPrivateKeyInfo(
                    new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), new DerOctetString(keyData), attributes, pubData);
            }
        }

        public override bool Equals(object o)
        {
            if (this == o)
            {
                return true;
            }

            if (!(o is AsymmetricEdDsaPrivateKey))
            {
                return false;
            }

            AsymmetricEdDsaPrivateKey other = (AsymmetricEdDsaPrivateKey)o;

            return Arrays.ConstantTimeAreEqual(this.keyData, other.keyData);
        }

        public override int GetHashCode()
        {
            return hashCode;
        }

        private int CalculateHashCode()
        {
            int result = Algorithm.GetHashCode();
            result = 31 * result + Arrays.GetHashCode(publicData);
            return result;
        }
        static byte[] ComputePublicData(Algorithm algorithm, byte[] secret)
        {
            byte[] publicKey;

            if (algorithm.Equals(EdEC.Algorithm.Ed448))
            {
                publicKey = new byte[EdEC.Ed448PublicKeySize];
                Org.BouncyCastle.Math.EC.Rfc8032.Ed448.GeneratePublicKey(secret, 0, publicKey, 0);
            }
            else
            {
                publicKey = new byte[EdEC.Ed25519PublicKeySize];
                Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.GeneratePublicKey(secret, 0, publicKey, 0);
            }

            return publicKey;
        }


        Func<IKey, IPrivateKeyEdDsaService> IServiceProvider<IPrivateKeyEdDsaService>.GetFunc(SecurityContext context)
        {
            return (key) => new PrivateKeyEdDsaService(key);
        }

        private class PrivateKeyEdDsaService : IPrivateKeyEdDsaService
        {
            private readonly bool approvedOnlyMode;
            private readonly IKey privateKey;

            public PrivateKeyEdDsaService(IKey privateKey)
            {
                this.approvedOnlyMode = CryptoServicesRegistrar.IsInApprovedOnlyMode();
                this.privateKey = privateKey;
            }

            public ISignatureFactory<A> CreateSignatureFactory<A>(A algorithmDetails) where A : IParameters<Algorithm>
            {
                CryptoServicesRegistrar.ApprovedModeCheck(approvedOnlyMode, "EdDSA");

                General.Utils.ApprovedModeCheck("service", algorithmDetails.Algorithm);

                if (algorithmDetails is EdEC.ParametersWithContext)
                {
                    return (ISignatureFactory<A>)new SignatureFactory<General.EdEC.ParametersWithContext>(algorithmDetails as General.EdEC.ParametersWithContext, new General.EdEC.SignerProvider(algorithmDetails as General.EdEC.ParametersWithContext, privateKey));
                }
                else
                {
                    return (ISignatureFactory<A>)new SignatureFactory<General.EdEC.Parameters>(algorithmDetails as General.EdEC.Parameters, new General.EdEC.SignerProvider(algorithmDetails as General.EdEC.Parameters, privateKey));
                }
            }
        }
    }
}

