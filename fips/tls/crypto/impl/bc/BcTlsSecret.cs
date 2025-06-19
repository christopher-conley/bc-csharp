using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fips;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>BC light-weight support class for handling TLS secrets and deriving key material and other secrets
    /// from them.</summary>
    public class BcTlsSecret
        : AbstractTlsSecret
    {
        public static BcTlsSecret Convert(BcTlsCrypto crypto, TlsSecret secret)
        {
            if (secret is BcTlsSecret)
                return (BcTlsSecret)secret;

            if (secret is AbstractTlsSecret)
            {
                AbstractTlsSecret abstractTlsSecret = (AbstractTlsSecret)secret;

                return crypto.AdoptLocalSecret(CopyData(abstractTlsSecret));
            }

            throw new ArgumentException("unrecognized TlsSecret - cannot copy data: " + Core.Platform.GetTypeName(secret));
        }

        protected readonly BcTlsCrypto m_crypto;

        public BcTlsSecret(BcTlsCrypto crypto, byte[] data)
            : base(data)
        {
            this.m_crypto = crypto;
        }

        public override TlsSecret DeriveUsingPrf(int prfAlgorithm, string label, byte[] seed, int length)
        {
            lock (this)
            {
                CheckAlive();

                switch (prfAlgorithm)
                {
                case PrfAlgorithm.tls13_hkdf_sha256:
                    return TlsCryptoUtilities.HkdfExpandLabel(this, CryptoHashAlgorithm.sha256, label, seed, length);
                case PrfAlgorithm.tls13_hkdf_sha384:
                    return TlsCryptoUtilities.HkdfExpandLabel(this, CryptoHashAlgorithm.sha384, label, seed, length);
                case PrfAlgorithm.tls13_hkdf_sm3:
                    return TlsCryptoUtilities.HkdfExpandLabel(this, CryptoHashAlgorithm.sm3, label, seed, length);
                default:
                    return m_crypto.AdoptLocalSecret(Prf(prfAlgorithm, label, seed, length));
                }
            }
        }

        public override TlsSecret HkdfExpand(int cryptoHashAlgorithm, byte[] info, int length)
        {
            lock (this)
            {
                if (length < 1)
                    return m_crypto.AdoptLocalSecret(TlsUtilities.EmptyBytes);

                int hashLen = TlsCryptoUtilities.GetHashOutputSize(cryptoHashAlgorithm);
                if (length > (255 * hashLen))
                    throw new ArgumentException("must be <= 255 * (output size of 'hashAlgorithm')", "length");

                CheckAlive();

                byte[] prk = m_data;

                FipsShs.AuthenticationParameters parameterSet = m_crypto.GetHmacParameters(cryptoHashAlgorithm);
                FipsShs.Key serviceKey = new FipsShs.Key(parameterSet, prk);
                IStreamCalculator<IBlockResult> hmac = CryptoServicesRegistrar
                    .CreateService(serviceKey)
                    .CreateMacFactory(parameterSet)
                    .CreateCalculator();

                byte[] okm = new byte[length];

                byte[] t = new byte[hashLen];
                byte counter = 0x00;

                int pos = 0;
                for (;;)
                {
                    hmac.Stream.Write(info, 0, info.Length);
                    hmac.Stream.WriteByte(++counter);
                    hmac.Stream.Close();
                    hmac.GetResult().Collect(t, 0);

                    int remaining = length - pos;
                    if (remaining <= hashLen)
                    {
                        Array.Copy(t, 0, okm, pos, remaining);
                        break;
                    }

                    Array.Copy(t, 0, okm, pos, hashLen);
                    pos += hashLen;
                    hmac.Stream.Write(t, 0, t.Length);
                }

                return m_crypto.AdoptLocalSecret(okm);
            }
        }

        public override TlsSecret HkdfExtract(int cryptoHashAlgorithm, TlsSecret ikm)
        {
            lock (this)
            {
                CheckAlive();

                byte[] salt = m_data;
                this.m_data = null;

                FipsShs.AuthenticationParameters parameterSet = m_crypto.GetHmacParameters(cryptoHashAlgorithm);
                FipsShs.Key serviceKey = new FipsShs.Key(parameterSet, salt);
                IStreamCalculator<IBlockResult> hmac = CryptoServicesRegistrar
                    .CreateService(serviceKey)
                    .CreateMacFactory(parameterSet)
                    .CreateCalculator();

                Convert(m_crypto, ikm).UpdateMac(hmac);

                hmac.Stream.Close();
                byte[] prk = hmac.GetResult().Collect();

                return m_crypto.AdoptLocalSecret(prk);
            }
        }

        protected override AbstractTlsCrypto Crypto
        {
            get { return m_crypto; }
        }

        protected virtual void HmacHash(int cryptoHashAlgorithm, byte[] secret, int secretOff, int secretLen,
            byte[] seed, byte[] output)
        {
            FipsShs.AuthenticationParameters parameterSet = m_crypto.GetHmacParameters(cryptoHashAlgorithm);
            FipsShs.Key serviceKey = new FipsShs.Key(parameterSet,
                Arrays.CopyOfRange(secret, secretOff, secretOff + secretLen));
            IStreamCalculator<IBlockResult> hmac = CryptoServicesRegistrar
                .CreateService(serviceKey)
                .CreateMacFactory(parameterSet)
                .CreateCalculator();

            byte[] a = seed;

            int macSize = (parameterSet.MacSizeInBits + 7) / 8;

            byte[] b1 = new byte[macSize];
            byte[] b2 = new byte[macSize];

            int pos = 0;
            while (pos < output.Length)
            {
                hmac.Stream.Write(a, 0, a.Length);
                hmac.Stream.Close();
                hmac.GetResult().Collect(b1, 0);
                a = b1;
                hmac.Stream.Write(a, 0, a.Length);
                hmac.Stream.Write(seed, 0, seed.Length);
                hmac.Stream.Close();
                hmac.GetResult().Collect(b2, 0);
                Array.Copy(b2, 0, output, pos, System.Math.Min(macSize, output.Length - pos));
                pos += macSize;
            }
        }

        protected virtual void HmacHashMd5(byte[] secret, int secretOff, int secretLen,
            byte[] seed, byte[] output)
        {
            Md5Hmac hmac = new Md5Hmac();
            hmac.SetKey(secret, secretOff, secretLen);

            byte[] a = seed;

            int macSize = hmac.MacLength;

            byte[] b1 = new byte[macSize];
            byte[] b2 = new byte[macSize];

            int pos = 0;
            while (pos < output.Length)
            {
                hmac.Update(a, 0, a.Length);
                hmac.CalculateMac(b1, 0);
                a = b1;
                hmac.Update(a, 0, a.Length);
                hmac.Update(seed, 0, seed.Length);
                hmac.CalculateMac(b2, 0);
                Array.Copy(b2, 0, output, pos, System.Math.Min(macSize, output.Length - pos));
                pos += macSize;
            }
        }

        protected virtual byte[] Prf(int prfAlgorithm, string label, byte[] seed, int length)
        {
            if (PrfAlgorithm.ssl_prf_legacy == prfAlgorithm)
                throw new ArgumentException("Unsupported PRF algorithm: " + PrfAlgorithm.GetText(prfAlgorithm));

            byte[] labelSeed = Arrays.Concatenate(Strings.ToByteArray(label), seed);

            if (PrfAlgorithm.tls_prf_legacy == prfAlgorithm)
                return Prf_1_0(labelSeed, length);

            return Prf_1_2(prfAlgorithm, labelSeed, length);
        }

        protected virtual byte[] Prf_1_0(byte[] labelSeed, int length)
        {
            int s_half = (m_data.Length + 1) / 2;

            byte[] b1 = new byte[length];
            HmacHashMd5(m_data, 0, s_half, labelSeed, b1);

            byte[] b2 = new byte[length];
            HmacHash(CryptoHashAlgorithm.sha1, m_data, m_data.Length - s_half, s_half, labelSeed, b2);

            for (int i = 0; i < length; i++)
            {
                b1[i] ^= b2[i];
            }
            return b1;
        }

        protected virtual byte[] Prf_1_2(int prfAlgorithm, byte[] labelSeed, int length)
        {
            int cryptoHashAlgorithm = TlsCryptoUtilities.GetHashForPrf(prfAlgorithm);
            byte[] result = new byte[length];
            HmacHash(cryptoHashAlgorithm, m_data, 0, m_data.Length, labelSeed, result);
            return result;
        }

        protected virtual void UpdateMac(IStreamCalculator<IBlockResult> mac)
        {
            lock (this)
            {
                CheckAlive();

                mac.Stream.Write(m_data, 0, m_data.Length);
            }
        }
    }
}
