using System;
using System.Globalization;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities.IO.Pem;

namespace Org.BouncyCastle.Tls.Core
{
    internal static class PemReaderUtilities
    {
        internal static PemObject ReadPemObject(Stream s)
        {
            using (FilterStreamReader r = new FilterStreamReader(s))
            {
                return new PemReader(r).ReadPemObject();
            }
        }

        private class FilterStreamReader
            : StreamReader
        {
            private static readonly CompareInfo InvariantCompareInfo = CultureInfo.InvariantCulture.CompareInfo;

            private bool include = false;

            internal FilterStreamReader(Stream s)
                : base(s)
            {
            }

            public override string ReadLine()
            {
                string line;
                while ((line = base.ReadLine()) != null)
                {
                    bool special = InvariantCompareInfo.IsPrefix(line, "-----", CompareOptions.Ordinal);

                    include ^= special;

                    if (include | special)
                        break;
                }
                return line;
            }
        }
    }
}
