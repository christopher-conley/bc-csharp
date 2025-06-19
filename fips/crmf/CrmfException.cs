using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Crmf
{
    public class CrmfException : Exception
    {
        public CrmfException()
        {
        }

        public CrmfException(string message) : base(message)
        {
        }

        public CrmfException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected CrmfException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}