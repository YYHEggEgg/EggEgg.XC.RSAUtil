using System.Security.Cryptography;

namespace XC.RSAUtil
{
    public abstract class RSAPemUtilBase : RSAUtilBase
    {
        public RSAPemUtilBase(string? privateKey = null, string? publicKey = null)
        {
        }

        protected abstract RSAParameters CreateRsapFromPrivateKey(string privateKey);
        protected abstract RSAParameters CreateRsapFromPublicKey(string publicKey);
    }
}
