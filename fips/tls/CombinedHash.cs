using System;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A combined hash, which implements md5(m) || sha1(m).</summary>
    public class CombinedHash
        : TlsHash
    {
        protected readonly TlsCrypto m_crypto;
        protected readonly TlsHash m_md5;
        protected readonly TlsHash m_sha1;

        public CombinedHash(TlsCrypto crypto)
            : this(crypto, crypto.CreateHash(CryptoHashAlgorithm.md5), crypto.CreateHash(CryptoHashAlgorithm.sha1))
        {
        }

        internal CombinedHash(TlsCrypto crypto, TlsHash md5, TlsHash sha1)
        {
            this.m_crypto = crypto;
            this.m_md5 = md5;
            this.m_sha1 = sha1;
        }

        public virtual void Update(byte[] input, int inOff, int len)
        {
            m_md5.Update(input, inOff, len);
            m_sha1.Update(input, inOff, len);
        }

        public virtual byte[] CalculateHash()
        {
            return Arrays.Concatenate(m_md5.CalculateHash(), m_sha1.CalculateHash());
        }

        public virtual void Reset()
        {
            m_md5.Reset();
            m_sha1.Reset();
        }
    }
}
