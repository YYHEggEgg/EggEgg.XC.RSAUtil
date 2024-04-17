using System;

namespace XC.RSAUtil
{
    public partial class RsaKeyGenerator
    {
        private const int MAXIMUM_KEYGEN_ATTEMPTS = 30;

        private static KeyResult PemKeyGenAttempt(RsaKeyPadding padding, int keySize, bool format = true)
        {
            int attempts = 0;
            Exception? latestException = null;
            while (attempts < MAXIMUM_KEYGEN_ATTEMPTS)
            {
                KeyResult keyResult;
                if (padding == RsaKeyPadding.Pkcs1)
                    keyResult = Pkcs1KeyCore(keySize);
                else if (padding == RsaKeyPadding.Pkcs8)
                    keyResult = Pkcs8KeyCore(keySize);
                else throw new NotImplementedException("The generating of this key type is not supported yet.");

                try
                {
                    RSAUtilBase.LoadRSAKey(keyResult.privateKey);
                    RSAUtilBase.LoadRSAKey(keyResult.publicKey);
                    if (!format)
                    {
                        (var begin, var end) = RsaPemFormatHelper.PemFormatParas[(padding, true)];
                        keyResult.privateKey = keyResult.privateKey.Replace(begin, "").Replace(end, "").Replace(Environment.NewLine,"");
                        (begin, end) = RsaPemFormatHelper.PemFormatParas[(padding, false)];
                        keyResult.publicKey = keyResult.publicKey.Replace(begin, "").Replace(end, "").Replace(Environment.NewLine, "");
                    }
                    return keyResult;
                }
                catch (Exception ex)
                {
                    latestException = ex;
                }
            }

            throw new InvalidOperationException($"The keygen method exceeded the maximum attempts count of {MAXIMUM_KEYGEN_ATTEMPTS}. Contact the nuget developer.", latestException);
        }
    }
}
