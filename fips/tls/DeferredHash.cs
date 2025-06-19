using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Buffers input until the hash algorithm is determined.</summary>
    internal sealed class DeferredHash
        : TlsHandshakeHash
    {
        private readonly TlsContext m_context;

        private readonly DigestInputBuffer m_buf;
        private int m_tracking;
        private bool m_sealed;

        internal DeferredHash(TlsContext context)
        {
            this.m_context = context;
            this.m_buf = new DigestInputBuffer();
            this.m_tracking = 0;
            this.m_sealed = false;
        }

        /// <exception cref="IOException"/>
        public void CopyBufferTo(Stream output)
        {
            m_buf.CopyInputTo(output);
        }

        public void ForceBuffering()
        {
            if (m_sealed)
                throw new InvalidOperationException("Too late to force buffering");
        }

        public void NotifyPrfDetermined()
        {
            SecurityParameters securityParameters = m_context.SecurityParameters;

            switch (securityParameters.PrfAlgorithm)
            {
            case PrfAlgorithm.ssl_prf_legacy:
            case PrfAlgorithm.tls_prf_legacy:
            {
                CheckTrackingHash(CryptoHashAlgorithm.md5);
                CheckTrackingHash(CryptoHashAlgorithm.sha1);
                break;
            }
            default:
            {
                CheckTrackingHash(securityParameters.PrfCryptoHashAlgorithm);
                break;
            }
            }
        }

        public void TrackHashAlgorithm(int cryptoHashAlgorithm)
        {
            if (m_sealed)
                throw new InvalidOperationException("Too late to track more hash algorithms");

            CheckTrackingHash(cryptoHashAlgorithm);
        }

        public void SealHashAlgorithms()
        {
            if (m_sealed)
                throw new InvalidOperationException("Already sealed");

            this.m_sealed = true;
        }

        public void StopTracking()
        {
            SecurityParameters securityParameters = m_context.SecurityParameters;

            switch (securityParameters.PrfAlgorithm)
            {
            case PrfAlgorithm.ssl_prf_legacy:
            case PrfAlgorithm.tls_prf_legacy:
            {
                m_tracking = (1 << CryptoHashAlgorithm.md5) | (1 << CryptoHashAlgorithm.sha1);
                break;
            }
            default:
            {
                m_tracking = 1 << securityParameters.PrfCryptoHashAlgorithm;
                break;
            }
            }

            this.m_sealed = true;
        }

        public TlsHash ForkPrfHash()
        {
            SecurityParameters securityParameters = m_context.SecurityParameters;

            TlsHash prfHash;
            switch (securityParameters.PrfAlgorithm)
            {
            case PrfAlgorithm.ssl_prf_legacy:
            case PrfAlgorithm.tls_prf_legacy:
            {
                TlsHash md5Hash = CreateHash(CryptoHashAlgorithm.md5);
                TlsHash sha1Hash = CreateHash(CryptoHashAlgorithm.sha1);
                prfHash = new CombinedHash(m_context.Crypto, md5Hash, sha1Hash);
                break;
            }
            default:
            {
                prfHash = CreateHash(securityParameters.PrfCryptoHashAlgorithm);
                break;
            }
            }

            m_buf.UpdateDigest(prfHash);

            return prfHash;
        }

        public byte[] GetFinalHash(int cryptoHashAlgorithm)
        {
            if (0 == (m_tracking & (1 << cryptoHashAlgorithm)))
                throw new InvalidOperationException("CryptoHashAlgorithm." + cryptoHashAlgorithm
                    + " is not being tracked");

            TlsHash hash = CreateHash(cryptoHashAlgorithm);
            m_buf.UpdateDigest(hash);

            return hash.CalculateHash();
        }

        public void Update(byte[] input, int inOff, int len)
        {
            m_buf.Write(input, inOff, len);
        }

        public byte[] CalculateHash()
        {
            throw new InvalidOperationException("Use 'ForkPrfHash' to get a definite hash");
        }

        public void Reset()
        {
            m_buf.SetLength(0);
        }

        private void CheckTrackingHash(int cryptoHashAlgorithm)
        {
            m_tracking |= 1 << cryptoHashAlgorithm;
        }

        private TlsHash CreateHash(int cryptoHashAlgorithm)
        {
            return m_context.Crypto.CreateHash(cryptoHashAlgorithm);
        }
    }
}
