using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Cert;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    public class X509CrlCollectionStore:IStore<X509Crl>
    {
        private ICollection<X509Crl> _local;

        /**
		 * Basic constructor.
		 *
		 * @param collection - initial contents for the store, this is copied.
		 */
        public X509CrlCollectionStore(
            ICollection<X509Crl> collection)
        {
            _local = new List<X509Crl>(collection);
        }

        /**
		 * Return the matches in the collection for the passed in selector.
		 *
		 * @param selector the selector to match against.
		 * @return a possibly empty collection of matching objects.
		 */

        ICollection<X509Crl> IStore<X509Crl>.GetMatches(ISelector<X509Crl> selector)
        {
            if (selector == null)
            {
                return  new List<X509Crl>(_local);
            }

            List<X509Crl> result = new List<X509Crl>();
            foreach (X509Crl obj in _local)
            {
                if (selector.Match(obj))
                    result.Add(obj);
            }

            return result;
        }

     
    }
}
