using System;
using System.Diagnostics.CodeAnalysis;

namespace XC.RSAUtil
{
    public class RsaDerTrialUtil : RSAUtilBase
    {
        public bool IsPrivate { get; private set; }
        public RsaKeyPadding Padding { get; private set; }
        public RsaKeyFormat Format { get; private set; }
        public RsaKeyFeature GetRSAKeyType() =>
            new RsaKeyFeature
            {
                IsPrivate = IsPrivate,
                Padding = Padding,
                Format = Format,
            };

        private RsaDerTrialUtil(RSAUtilBase wrapped, bool isPrivate, RsaKeyPadding padding, RsaKeyFormat format)
        {
            IsPrivate = isPrivate;
            Padding = padding;
            Format = format;

            PrivateRsa = wrapped.PrivateRsa;
            PublicRsa = wrapped.PublicRsa;
        }

        public static bool TryParseAsPublicPkcs1(byte[] rsaKeyBin, [NotNullWhen(true)] out RsaDerTrialUtil? result)
        {
            try
            {
                var rsaKey = RsaPemFormatHelper.Pkcs1PublicKeyFormat(Convert.ToBase64String(rsaKeyBin));
                result = new RsaDerTrialUtil(new RsaPkcs1Util(publicKey: rsaKey), false, RsaKeyPadding.Pkcs1, RsaKeyFormat.Der);
                return true;
            }
            catch
            {
                result = null;
                return false;
            }
        }

        public static bool TryParseAsPublicPkcs8(byte[] rsaKeyBin, [NotNullWhen(true)] out RsaDerTrialUtil? result)
        {
            try
            {
                var rsaKey = RsaPemFormatHelper.Pkcs8PublicKeyFormat(Convert.ToBase64String(rsaKeyBin));
                result = new RsaDerTrialUtil(new RsaPkcs8Util(publicKey: rsaKey), false, RsaKeyPadding.Pkcs8, RsaKeyFormat.Der);
                return true;
            }
            catch
            {
                result = null;
                return false;
            }
        }
        
        public static bool TryParseAsPrivatePkcs1(byte[] rsaKeyBin, [NotNullWhen(true)] out RsaDerTrialUtil? result)
        {
            try
            {
                var rsaKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(Convert.ToBase64String(rsaKeyBin));
                result = new RsaDerTrialUtil(new RsaPkcs1Util(privateKey: rsaKey), true, RsaKeyPadding.Pkcs1, RsaKeyFormat.Der);
                return true;
            }
            catch
            {
                result = null;
                return false;
            }
        }
        
        public static bool TryParseAsPrivatePkcs8(byte[] rsaKeyBin, [NotNullWhen(true)] out RsaDerTrialUtil? result)
        {
            try
            {
                var rsaKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormat(Convert.ToBase64String(rsaKeyBin));
                result = new RsaDerTrialUtil(new RsaPkcs8Util(privateKey: rsaKey), true, RsaKeyPadding.Pkcs8, RsaKeyFormat.Der);
                return true;
            }
            catch
            {
                result = null;
                return false;
            }
        }
    }
}
