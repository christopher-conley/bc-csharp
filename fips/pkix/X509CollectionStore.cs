using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    public class X509CollectionStore:IStore<X509Certificate>
    {
        private ICollection<X509Certificate> _local;

        /**
		 * Basic constructor.
		 *
		 * @param collection - initial contents for the store, this is copied.
		 */
        public X509CollectionStore(
            ICollection<X509Certificate> collection)
        {
            _local = new List<X509Certificate>(collection);
        }

        /**
		 * Return the matches in the collection for the passed in selector.
		 *
		 * @param selector the selector to match against.
		 * @return a possibly empty collection of matching objects.
		 */

        ICollection<X509Certificate> IStore<X509Certificate>.GetMatches(ISelector<X509Certificate> selector)
        {
            if (selector == null)
            {
                return  new List<X509Certificate>(_local);
            }

            List<X509Certificate> result = new List<X509Certificate>();
            foreach (X509Certificate obj in _local)
            {
                if (selector.Match(obj))
                    result.Add(obj);
            }

            return result;
        }

     
    }
}
