using System;

using Org.BouncyCastle.Tls.Core;

namespace Org.BouncyCastle.Tls
{
    public class DefaultTlsHeartbeat
        : TlsHeartbeat
    {
        private readonly int idleMillis, timeoutMillis;

        private int counter = 0;

        public DefaultTlsHeartbeat(int idleMillis, int timeoutMillis)
        {
            if (idleMillis <= 0)
                throw new ArgumentException("must be > 0", "idleMillis");
            if (timeoutMillis <= 0)
                throw new ArgumentException("must be > 0", "timeoutMillis");

            this.idleMillis = idleMillis;
            this.timeoutMillis = timeoutMillis;
        }

        public virtual byte[] GeneratePayload()
        {
            lock (this)
            {
                // NOTE: The counter naturally wraps back to 0
                return Pack.Int32_To_BE(++counter);
            }
        }

        public virtual int IdleMillis
        {
            get { return idleMillis; }
        }

        public virtual int TimeoutMillis
        {
            get { return timeoutMillis; }
        }
    }
}
