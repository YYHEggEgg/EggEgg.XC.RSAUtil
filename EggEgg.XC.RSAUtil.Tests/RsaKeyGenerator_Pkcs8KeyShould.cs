namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RsaKeyGenerator_Pkcs8KeyShould
{
    [Theory]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2048)]
    public void Pkcs8Key_AssertByLoading(int keySize)
    {
        var keyResult = RsaKeyGenerator.Pkcs8Key(keySize);

        var pubKeyType = RSAUtilBase.TreatRSAKeyType(keyResult.publicKey);
        Assert.Equal(RsaKeyFormat.Pem, pubKeyType.Format);
        Assert.Equal(RsaKeyPadding.Pkcs8, pubKeyType.Padding);
        Assert.False(pubKeyType.IsPrivate);

        var priKeyType = RSAUtilBase.TreatRSAKeyType(keyResult.privateKey);
        Assert.Equal(RsaKeyFormat.Pem, priKeyType.Format);
        Assert.Equal(RsaKeyPadding.Pkcs8, priKeyType.Padding);
        Assert.True(priKeyType.IsPrivate);

        var rsa = RSAUtilBase.LoadRSAKey(keyResult.privateKey);
        Assert.Equal(keySize, rsa.PublicRsa?.KeySize);
        Assert.Equal(keySize, rsa.PrivateRsa?.KeySize);
    }
}
