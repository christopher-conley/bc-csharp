
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Cms
{
    internal class CmsEnvelopedHelper
    {
        internal static RecipientInformationStore BuildRecipientInformationStore(
            Asn1Set recipientInfos, AlgorithmIdentifier messageAlgorithm, ICmsSecureReadable secureReadable)
        {
            return BuildRecipientInformationStore(recipientInfos, messageAlgorithm, secureReadable, null);
        }

        internal static RecipientInformationStore BuildRecipientInformationStore(
            Asn1Set recipientInfos, AlgorithmIdentifier messageAlgorithm, ICmsSecureReadable secureReadable, IAuthAttributesProvider additionalData)
        {
            IList<RecipientInformation> infos = new List<RecipientInformation>();
            for (int i = 0; i != recipientInfos.Count; i++)
            {
                RecipientInfo info = RecipientInfo.GetInstance(recipientInfos[i]);

                ReadRecipientInfo(infos, info, messageAlgorithm, secureReadable, additionalData);
            }
            return new RecipientInformationStore(infos);
        }

        private static void ReadRecipientInfo(IList<RecipientInformation> infos, RecipientInfo info, AlgorithmIdentifier messageAlgorithm, ICmsSecureReadable secureReadable, IAuthAttributesProvider additionalData)
        {
            Asn1Encodable recipInfo = info.Info;
            if (recipInfo is KeyTransRecipientInfo keyTrans)
            {
                infos.Add(new KeyTransRecipientInformation(keyTrans, messageAlgorithm, secureReadable, additionalData));
            }
            //else if (recipInfo is KekRecipientInfo kek)
            //{
            //    infos.Add(new KEKRecipientInformation(kek, messageAlgorithm, secureReadable, additionalData));
            //}
            //else if (recipInfo is KeyAgreeRecipientInfo keyAgree)
            //{
            //    KeyAgreeRecipientInformation.ReadRecipientInfo(infos, keyAgree, messageAlgorithm, secureReadable, additionalData);
            //}
            //else if (recipInfo is PasswordRecipientInfo password)
            //{
            //    infos.Add(new PasswordRecipientInformation(password, messageAlgorithm, secureReadable, additionalData));
            //}
        }

        internal class CmsEnvelopedSecureReadable : ICmsSecureReadable
        {
            //private readonly AlgorithmIdentifier encAlg;
            private readonly CmsReadable readable;

            public CmsEnvelopedSecureReadable(AlgorithmIdentifier encAlg, CmsReadable readable)
            {
                //this.encAlg = encAlg;
                this.readable = readable;
            }

            public Stream GetInputStream()
            {
                return readable.GetInputStream();
            }
        }
    }
}