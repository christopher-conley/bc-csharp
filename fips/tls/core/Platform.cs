using System;

#if SILVERLIGHT || PORTABLE
using System.Collections.Generic;
#else
using System.Collections;
#endif

namespace Org.BouncyCastle.Tls.Core
{
    internal sealed class Platform
    {
        private Platform()
        {
        }

#if SILVERLIGHT || PORTABLE
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Dictionary<object, object>(capacity);
        }
#else
        internal static System.Collections.IDictionary CreateHashtable(int capacity)
        {
            return new Hashtable(capacity);
        }
#endif

        internal static string GetTypeName(object obj)
        {
            return obj.GetType().FullName;
        }
    }
}
