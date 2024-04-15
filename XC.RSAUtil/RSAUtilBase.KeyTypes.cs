using System;
using System.Text;

namespace XC.RSAUtil
{
    public abstract partial class RSAUtilBase
    {
        /// <summary>
        /// Load the rsa key string as <see cref="RSAUtilBase"/>.
        /// </summary>
        /// <param name="rsaKey">The string rsa key, support public/private, PKCS1/PKCS8/Xml all.</param>
        /// <returns></returns>
        /// <remarks>This overload only supports PEM/XML keys. If you want to allow .der keys, use <see cref="LoadRSAKey(byte[])"/>.</remarks>
        public static RSAUtilBase LoadRSAKey(string rsaKey)
        {
            var keyType = TreatRSAKeyType(rsaKey);
            // PKCS8 Padding
            if (keyType.Padding == RsaKeyPadding.Pkcs8 && !keyType.IsPrivate)
                return new RsaPkcs8Util(publicKey: rsaKey);
            else if (keyType.Padding == RsaKeyPadding.Pkcs8 && keyType.IsPrivate)
                return new RsaPkcs8Util(privateKey: rsaKey);
            // PKCS1 Padding
            else if (keyType.Padding == RsaKeyPadding.Pkcs1 && !keyType.IsPrivate)
                return new RsaPkcs1Util(publicKey: rsaKey);
            else if (keyType.Padding == RsaKeyPadding.Pkcs1 && keyType.IsPrivate)
                return new RsaPkcs1Util(privateKey: rsaKey);
            // .NET XML Format
            else if (keyType.Padding == RsaKeyPadding.Xml && !keyType.IsPrivate)
                return new RsaXmlUtil(publicKey: rsaKey);
            else if (keyType.Padding == RsaKeyPadding.Xml && keyType.IsPrivate)
                return new RsaXmlUtil(privateKey: rsaKey);
            else throw new ArgumentException("Invalid RSA Key!", nameof(rsaKey));
        }

        /// <summary>
        /// Return a <see cref="RsaKeyFeature"/> object that represents the type of string <paramref name="rsaKey"/>.
        /// </summary>
        /// <remarks>This overload only supports PEM/XML keys. If you want to allow .der keys, use <see cref="TreatRSAKeyType(byte[])"/>.</remarks>
        public static RsaKeyFeature TreatRSAKeyType(string rsaKey)
        {
            rsaKey = rsaKey.Trim();
            foreach (var pair in RsaPemFormatHelper.PemFormatParas)
            {
                (string begin, string end) = pair.Value;
                if (rsaKey.StartsWith(begin) && rsaKey.EndsWith(end))
                    return new RsaKeyFeature
                    {
                        Padding = pair.Key.Padding,
                        IsPrivate = pair.Key.IsPrivate,
                        Format = RsaKeyFormat.Pem,
                    };
            }

            // .NET XML Format
            if (rsaKey.StartsWith("<RSAKeyValue>"))
            {
                if (rsaKey.Contains("<InverseQ>"))
                    return new RsaKeyFeature
                    {
                        IsPrivate = true,
                        Padding = RsaKeyPadding.Xml,
                        Format = RsaKeyFormat.Xml,
                    };
                else
                    return new RsaKeyFeature
                    {
                        IsPrivate = false,
                        Padding = RsaKeyPadding.Xml,
                        Format = RsaKeyFormat.Xml,
                    };
            }
            else throw new ArgumentException("Invalid RSA Key!", nameof(rsaKey));
        }

        /// <summary>
        /// Load the rsa key as <see cref="RSAUtilBase"/>.
        /// </summary>
        /// <param name="rsaKeyBin">The bytes representing a rsa key, support public/private, PKCS1/PKCS8/Xml, .pem/.der all.</param>
        /// <returns></returns>
        /// <remarks>If you want to parse PEM keys with this method as well, convert the readable string into a byte array with <see cref="Encoding.GetBytes(string)"/> directly.</remarks>
        public static RSAUtilBase LoadRSAKey(byte[] rsaKeyBin)
        {
            if (IsStringKey(rsaKeyBin))
                return LoadRSAKey(Encoding.Default.GetString(rsaKeyBin));
            else return LoadRSAKeyBinCore(rsaKeyBin);
        }

        /// <summary>
        /// Return a <see cref="RsaKeyFeature"/> object that represents the type of byte array <paramref name="rsaKeyBin"/>.
        /// </summary>
        /// <remarks>If you want to parse PEM keys with this method as well, convert the readable string into a byte array with <see cref="Encoding.GetBytes(string)"/> directly.</remarks>
        public static RsaKeyFeature TreatRSAKeyType(byte[] rsaKeyBin)
        {
            if (IsStringKey(rsaKeyBin))
                return TreatRSAKeyType(Encoding.Default.GetString(rsaKeyBin));

            return LoadRSAKeyBinCore(rsaKeyBin).GetRSAKeyType();
        }

        private static RsaDerTrialUtil LoadRSAKeyBinCore(byte[] rsaKeyBin)
        {
            if (RsaDerTrialUtil.TryParseAsPublicPkcs1(rsaKeyBin, out var res)) return res;
            else if (RsaDerTrialUtil.TryParseAsPublicPkcs8(rsaKeyBin, out res)) return res;
            else if (RsaDerTrialUtil.TryParseAsPrivatePkcs1(rsaKeyBin, out res)) return res;
            else if (RsaDerTrialUtil.TryParseAsPrivatePkcs8(rsaKeyBin, out res)) return res;
            else throw new ArgumentException("Invalid RSA Key!", nameof(rsaKeyBin));
        }

        private static bool IsStringKey(byte[] rsaKeyBin)
        {
            try
            {
                var start = Encoding.Default.GetString(rsaKeyBin, 0, 10);
                return start.StartsWith("-----") || start.StartsWith("<RSAKey");
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Calculate the length (bits) from a RSA key's Modulus Length.
        /// </summary>
        /// <param name="modulus"></param>
        /// <returns></returns>
        public static int CalculateKeyLength(byte[] modulus) =>
            (int)Math.Pow(2, Math.Log(256, 2)) * 8;
    }
}
