using System;
using System.Text;

namespace XC.RSAUtil
{
    public struct BinaryKeyResult
    {
        public RsaKeyFormat Format;
        public RsaKeyPadding Padding;
        public int KeySize;
        public byte[] PublicKey;
        public byte[] PrivateKey;

        public RSAUtilBase GetRSAInstance() => RSAUtilBase.LoadRSAKey(PrivateKey);
    }

    public partial class RsaKeyGenerator
    {
        public static BinaryKeyResult GetKey(RsaKeyFeature keyType, int keySize)
        {
            keyType.Validate(nameof(keyType));
            var pemKeys = GetStringKeyCore(keyType, keySize);

            if (keyType.Format == RsaKeyFormat.Der)
            {
#if false
                Console.WriteLine(pemKeys.publicKey);
                Console.WriteLine(RsaPemFormatHelper.PemRsaKeyFormatRemove(pemKeys.publicKey, keyType.Padding, false));
#endif
                return new BinaryKeyResult
                {
                    Format = keyType.Format,
                    Padding = keyType.Padding,
                    KeySize = keySize,
                    PrivateKey = Convert.FromBase64String(RsaPemFormatHelper.PemRsaKeyFormatRemove(pemKeys.privateKey, keyType.Padding, true)),
                    PublicKey = Convert.FromBase64String(RsaPemFormatHelper.PemRsaKeyFormatRemove(pemKeys.publicKey, keyType.Padding, false)),
                };
            }

            return new BinaryKeyResult
            {
                Format = keyType.Format,
                Padding = keyType.Padding,
                KeySize = keySize,
                PrivateKey = Encoding.UTF8.GetBytes(pemKeys.privateKey),
                PublicKey = Encoding.UTF8.GetBytes(pemKeys.publicKey),
            };
        }

        private static KeyResult GetStringKeyCore(RsaKeyFeature keyType, int keySize, bool format = true)
        {
            if (keyType.Format == RsaKeyFormat.Xml)
                return XmlKey(keySize);
            else return PemKeyGenAttempt(keyType.Padding, keySize, format);
        }

        public static BinaryKeyResult GetKey(RsaKeyFormat format, RsaKeyPadding padding, int keySize) => GetKey(new RsaKeyFeature
            {
                Format = format,
                Padding = padding,
                IsPrivate = true,
            }, keySize);
    }
}
