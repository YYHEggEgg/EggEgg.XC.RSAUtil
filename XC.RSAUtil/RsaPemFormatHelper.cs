using System;
using System.Collections.Generic;

namespace XC.RSAUtil
{
    public class RsaPemFormatHelper
    {
        internal static readonly Dictionary<(RsaKeyPadding Padding, bool IsPrivate), (string Begin, string End)> PemFormatParas = new Dictionary<(RsaKeyPadding Padding, bool IsPrivate), (string Begin, string End)>()
        {
            { (RsaKeyPadding.Pkcs1, false), ("-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----") },
            { (RsaKeyPadding.Pkcs8, false), ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----") },
            { (RsaKeyPadding.Pkcs1, true), ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----") },
            { (RsaKeyPadding.Pkcs8, true), ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----") },
        };

        /// <summary>
        /// Format any PEM RSA key
        /// </summary>
        /// <returns>A string ensured to match PEM format</returns>
        public static string PemRsaKeyFormat(string str, RsaKeyPadding targetPadding, bool isPrivate)
        {
            (string begin, string end) = PemFormatParas[(targetPadding, isPrivate)];
            
            if (str.StartsWith(begin))
            {
                return str;
            }

            List<string> res = new List<string>();
            res.Add(begin);

            int pos = 0;

            while (pos < str.Length)
            {
                var count = str.Length - pos < 64 ? str.Length - pos : 64;
                res.Add(str.Substring(pos, count));
                pos += count;
            }

            res.Add($"{end}{Environment.NewLine}");
            var resStr = string.Join(Environment.NewLine, res);
            return resStr;
        }

        /// <summary>
        /// Remove any PEM RSA key's begin and end
        /// </summary>
        /// <returns>A string ensured to match PEM format</returns>
        public static string PemRsaKeyFormatRemove(string str, RsaKeyPadding targetPadding, bool isPrivate)
        {
            (string begin, string end) = PemFormatParas[(targetPadding, isPrivate)];
            
            if (!str.StartsWith(begin))
            {
                return str;
            }
            return str.Replace(begin, string.Empty).Replace(end, string.Empty)
                .Replace(Environment.NewLine, string.Empty);
        }


        /// <summary>
        /// Format Pkcs1 format private key
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs1PrivateKeyFormat(string str) =>
            PemRsaKeyFormat(str, RsaKeyPadding.Pkcs1, true);

        /// <summary>
        /// Remove the Pkcs8 format private key format
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs8PrivateKeyFormatRemove(string str) =>
            PemRsaKeyFormatRemove(str, RsaKeyPadding.Pkcs8, true);

        /// <summary>
        /// Format Pkcs8 format private key
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs8PrivateKeyFormat(string str) =>
            PemRsaKeyFormat(str, RsaKeyPadding.Pkcs8, true);

        /// <summary>
        /// Remove the Pkcs1 format private key format
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs1PrivateKeyFormatRemove(string str) =>
            PemRsaKeyFormatRemove(str, RsaKeyPadding.Pkcs1, true);

        /// <summary>
        /// Format Pkcs8 format public key
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs8PublicKeyFormat(string str) =>
            PemRsaKeyFormat(str, RsaKeyPadding.Pkcs8, false);

        /// <summary>
        /// Remove the Pkcs8 format public key format
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs8PublicKeyFormatRemove(string str) =>
            PemRsaKeyFormatRemove(str, RsaKeyPadding.Pkcs8, false);

        /// <summary>
        /// Format Pkcs1 format public key
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs1PublicKeyFormat(string str) =>
            PemRsaKeyFormat(str, RsaKeyPadding.Pkcs1, false);

        /// <summary>
        /// Remove the Pkcs1 format public key format
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string Pkcs1PublicKeyFormatRemove(string str) =>
            PemRsaKeyFormatRemove(str, RsaKeyPadding.Pkcs1, false);
    }
}
