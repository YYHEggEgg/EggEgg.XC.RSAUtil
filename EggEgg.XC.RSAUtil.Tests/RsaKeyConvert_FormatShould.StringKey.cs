namespace YYHEggEgg.XC.RSAUtil.Tests;

public class RsaKeyConvert_FormatShould
{
    private RsaKeyFeature Pkcs1PrivateKeyType = new()
    {
        IsPrivate = true,
        Padding = RsaKeyPadding.Pkcs1,
        Format = RsaKeyFormat.Pem,
    }; 
    private RsaKeyFeature Pkcs8PrivateKeyType = new()
    {
        IsPrivate = true,
        Padding = RsaKeyPadding.Pkcs8,
        Format = RsaKeyFormat.Pem,
    };
    private RsaKeyFeature XmlPrivateKeyType = new()
    {
        IsPrivate = true,
        Padding = RsaKeyPadding.Xml,
        Format = RsaKeyFormat.Xml,
    };
    private RsaKeyFeature Pkcs1PublicKeyType = new()
    {
        IsPrivate = false,
        Padding = RsaKeyPadding.Pkcs1,
        Format = RsaKeyFormat.Pem,
    };
    private RsaKeyFeature Pkcs8PublicKeyType = new()
    {
        IsPrivate = false,
        Padding = RsaKeyPadding.Pkcs8,
        Format = RsaKeyFormat.Pem,
    };
    private RsaKeyFeature XmlPublicKeyType = new()
    {
        IsPrivate = false,
        Padding = RsaKeyPadding.Xml,
        Format = RsaKeyFormat.Xml,
    };

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAKeys.Pkcs8PrivateKey_5)]
    public void Format_Private_Pkcs1ToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs1PrivateKeyType, Pkcs8PrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAKeys.Pkcs1PrivateKey_5)]
    public void Format_Private_Pkcs8ToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs8PrivateKeyType, Pkcs1PrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAKeys.XmlPrivateKey_5)]
    public void Format_Private_Pkcs1ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs1PrivateKeyType, XmlPrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPrivateKey_2, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.XmlPrivateKey_3, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAKeys.Pkcs1PrivateKey_5)]
    public void Format_Private_XmlToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, XmlPrivateKeyType, Pkcs1PrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAKeys.XmlPrivateKey_5)]
    public void Format_Private_Pkcs8ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs8PrivateKeyType, XmlPrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPrivateKey_2, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.XmlPrivateKey_3, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAKeys.Pkcs8PrivateKey_5)]
    public void Format_Private_XmlToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, XmlPrivateKeyType, Pkcs8PrivateKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAKeys.Pkcs8PublicKey_5)]
    public void Format_Public_Pkcs1ToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs1PublicKeyType, Pkcs8PublicKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAKeys.Pkcs1PublicKey_5)]
    public void Format_Public_Pkcs8ToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs8PublicKeyType, Pkcs1PublicKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAKeys.XmlPublicKey_5)]
    public void Format_Public_Pkcs1ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs1PublicKeyType, XmlPublicKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPublicKey_2, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.XmlPublicKey_3, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAKeys.Pkcs1PublicKey_5)]
    public void Format_Public_XmlToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, XmlPublicKeyType, Pkcs1PublicKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAKeys.XmlPublicKey_5)]
    public void Format_Public_Pkcs8ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, Pkcs8PublicKeyType, XmlPublicKeyType));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPublicKey_2, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.XmlPublicKey_3, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAKeys.Pkcs8PublicKey_5)]
    public void Format_Public_XmlToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, XmlPublicKeyType, Pkcs8PublicKeyType));
    }
}
