using System.Security.Cryptography;

namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RSAUtilBase_SignDataShould
{
    [Theory]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Decrypted_RSA4_01_Base64, TestRSAData.Signature_RSA4_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_4.der", TestRSAData.Decrypted_RSA4_02_Base64, TestRSAData.Signature_RSA4_02_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs1PrivateKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Decrypted_RSA5_01_Base64, TestRSAData.Signature_RSA5_01_Base64)]
    [InlineData("TestDerKeys/Pkcs8PrivateKey_5.der", TestRSAData.Decrypted_RSA5_02_Base64, TestRSAData.Signature_RSA5_02_Base64)]
    public void SignData_DerKey(string rsakeyPath, string decrypted_base64, string expected_sign_base64)
    {
        var key = RSAUtilBase.LoadRSAKey(File.ReadAllBytes(rsakeyPath));
        var res = key.SignData(Convert.FromBase64String(decrypted_base64), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Assert.Equal(expected_sign_base64, Convert.ToBase64String(res));
    }
}
