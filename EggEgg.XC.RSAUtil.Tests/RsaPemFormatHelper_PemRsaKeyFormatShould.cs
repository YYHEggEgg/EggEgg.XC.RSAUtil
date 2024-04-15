namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RsaPemFormatHelper_PemRsaKeyFormatShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5)]
    public void PemRsaKeyFormat_Pkcs1Private(string pemKey)
    {
        Assert.Equal(pemKey.ReplaceLineEndings(), RsaPemFormatHelper.PemRsaKeyFormat(pemKey, RsaKeyPadding.Pkcs1, true));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5)]
    public void PemRsaKeyFormat_Pkcs1Public(string pemKey)
    {
        Assert.Equal(pemKey.ReplaceLineEndings(), RsaPemFormatHelper.PemRsaKeyFormat(pemKey, RsaKeyPadding.Pkcs1, false));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5)]
    public void PemRsaKeyFormat_Pkcs8Private(string pemKey)
    {
        Assert.Equal(pemKey.ReplaceLineEndings(), RsaPemFormatHelper.PemRsaKeyFormat(pemKey, RsaKeyPadding.Pkcs8, true));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5)]
    public void PemRsaKeyFormat_Pkcs8Public(string pemKey)
    {
        Assert.Equal(pemKey.ReplaceLineEndings(), RsaPemFormatHelper.PemRsaKeyFormat(pemKey, RsaKeyPadding.Pkcs8, false));
    }
}
