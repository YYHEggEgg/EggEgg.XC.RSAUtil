namespace YYHEggEgg.XC.RSAUtil.Tests;

public partial class RsaKeyGenerator_Pkcs1KeyShould
{
    [Theory]
    [InlineData(512)]
    [InlineData(1024)]
    [InlineData(2048)]
    public void Pkcs1Key_AssertByLoading(int keySize)
    {
        var keyResult = RsaKeyGenerator.Pkcs1Key(keySize);

        var pubKeyType = RSAUtilBase.TreatRSAKeyType(keyResult.publicKey);
        Assert.Equal(RsaKeyFormat.Pem, pubKeyType.Format);
        Assert.Equal(RsaKeyPadding.Pkcs1, pubKeyType.Padding);
        Assert.False(pubKeyType.IsPrivate);

        var priKeyType = RSAUtilBase.TreatRSAKeyType(keyResult.privateKey);
        Assert.Equal(RsaKeyFormat.Pem, priKeyType.Format);
        Assert.Equal(RsaKeyPadding.Pkcs1, priKeyType.Padding);
        Assert.True(priKeyType.IsPrivate);

        var rsa = RSAUtilBase.LoadRSAKey(keyResult.privateKey);
        Assert.Equal(keySize, rsa.PublicRsa?.KeySize);
        Assert.Equal(keySize, rsa.PrivateRsa?.KeySize);
    }
}
