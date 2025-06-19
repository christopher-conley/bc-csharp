using Org.BouncyCastle.Utilities;
using System.Collections.Generic;

namespace Org.BouncyCastle.Ocsp
{
    internal sealed class StoreImpl<T>
        : IStore<T>
    {
        private readonly List<T> m_contents;

        internal StoreImpl(IEnumerable<T> e)
        {
            m_contents = new List<T>(e);
        }

        public ICollection<T> GetMatches(ISelector<T> selector)
        {
            IList<T> certs = new List<T>();

            foreach (T candidate in m_contents)
            {
                if (selector == null || selector.Match(candidate))
                {
                    certs.Add(candidate);
                }
            }

            return certs;
        }
    }
}
