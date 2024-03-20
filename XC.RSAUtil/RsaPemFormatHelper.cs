using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

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

        private static Regex invisibleWorker = new Regex(@"\s+", RegexOptions.Compiled);
        private static Regex base64Worker = new Regex("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$", RegexOptions.Compiled | RegexOptions.Singleline);

        /// <summary>
        /// Format any PEM RSA key
        /// </summary>
        /// <returns>A string ensured to match PEM format</returns>
        public static string PemRsaKeyFormat(string str, RsaKeyPadding targetPadding, bool isPrivate)
        {
            (string begin, string end) = PemFormatParas[(targetPadding, isPrivate)];
            
            str = PemRsaKeyFormatRemove(str, targetPadding, isPrivate);
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
            
            str = str.Trim();
            if (str.StartsWith(begin))
            {
                str = str.Substring(begin.Length);
            }
            if (str.EndsWith(end))
            {
                str = str.Substring(0, str.Length - end.Length);
            }

            str = invisibleWorker.Replace(str, "");
            if (!base64Worker.IsMatch(str))
                throw new ArgumentException("The input string is neither a valid base64 string nor a PEM format.");
            return str;
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
