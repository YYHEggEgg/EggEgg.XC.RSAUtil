using System.Security.Cryptography;

namespace YYHEggEgg.XC.RSAUtil.Tests;

public class RSAUtilBase_SignDataShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    public void SignData(string rsakey, string decrypted_base64, string expected_sign_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(rsakey);
        var res = key.SignData(Convert.FromBase64String(decrypted_base64), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.Equal(expected_sign_base64, Convert.ToBase64String(res));
    }
}