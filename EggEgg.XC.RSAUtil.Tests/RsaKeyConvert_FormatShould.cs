namespace YYHEggEgg.XC.RSAUtil.Tests;

public class RsaKeyConvert_FormatShould
{
    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAKeys.Pkcs8PrivateKey_5)]
    public void Format_Private_Pkcs1ToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Pkcs1 | RsaKeyType.Private, RsaKeyType.Pkcs8 | RsaKeyType.Private));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAKeys.Pkcs1PrivateKey_5)]
    public void Format_Private_Pkcs8ToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Pkcs8 | RsaKeyType.Private, RsaKeyType.Pkcs1 | RsaKeyType.Private));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_2, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_3, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_4, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PrivateKey_5, TestRSAKeys.XmlPrivateKey_5)]
    public void Format_Private_Pkcs1ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Pkcs1 | RsaKeyType.Private, RsaKeyType.Xml | RsaKeyType.Private));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPrivateKey_2, TestRSAKeys.Pkcs1PrivateKey_2)]
    [InlineData(TestRSAKeys.XmlPrivateKey_3, TestRSAKeys.Pkcs1PrivateKey_3)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAKeys.Pkcs1PrivateKey_4)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAKeys.Pkcs1PrivateKey_5)]
    public void Format_Private_XmlToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Xml | RsaKeyType.Private, RsaKeyType.Pkcs1 | RsaKeyType.Private));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_2, TestRSAKeys.XmlPrivateKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_3, TestRSAKeys.XmlPrivateKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_4, TestRSAKeys.XmlPrivateKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PrivateKey_5, TestRSAKeys.XmlPrivateKey_5)]
    public void Format_Private_Pkcs8ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Pkcs8 | RsaKeyType.Private, RsaKeyType.Xml | RsaKeyType.Private));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPrivateKey_2, TestRSAKeys.Pkcs8PrivateKey_2)]
    [InlineData(TestRSAKeys.XmlPrivateKey_3, TestRSAKeys.Pkcs8PrivateKey_3)]
    [InlineData(TestRSAKeys.XmlPrivateKey_4, TestRSAKeys.Pkcs8PrivateKey_4)]
    [InlineData(TestRSAKeys.XmlPrivateKey_5, TestRSAKeys.Pkcs8PrivateKey_5)]
    public void Format_Private_XmlToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Xml | RsaKeyType.Private, RsaKeyType.Pkcs8 | RsaKeyType.Private));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAKeys.Pkcs8PublicKey_5)]
    public void Format_Public_Pkcs1ToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Pkcs1 | RsaKeyType.Public, RsaKeyType.Pkcs8 | RsaKeyType.Public));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAKeys.Pkcs1PublicKey_5)]
    public void Format_Public_Pkcs8ToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Pkcs8 | RsaKeyType.Public, RsaKeyType.Pkcs1 | RsaKeyType.Public));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_2, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_3, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_4, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs1PublicKey_5, TestRSAKeys.XmlPublicKey_5)]
    public void Format_Public_Pkcs1ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Pkcs1 | RsaKeyType.Public, RsaKeyType.Xml | RsaKeyType.Public));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPublicKey_2, TestRSAKeys.Pkcs1PublicKey_2)]
    [InlineData(TestRSAKeys.XmlPublicKey_3, TestRSAKeys.Pkcs1PublicKey_3)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAKeys.Pkcs1PublicKey_4)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAKeys.Pkcs1PublicKey_5)]
    public void Format_Public_XmlToPkcs1(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Xml | RsaKeyType.Public, RsaKeyType.Pkcs1 | RsaKeyType.Public));
    }

    [Theory]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_2, TestRSAKeys.XmlPublicKey_2)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_3, TestRSAKeys.XmlPublicKey_3)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_4, TestRSAKeys.XmlPublicKey_4)]
    [InlineData(TestRSAKeys.Pkcs8PublicKey_5, TestRSAKeys.XmlPublicKey_5)]
    public void Format_Public_Pkcs8ToXml(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Pkcs8 | RsaKeyType.Public, RsaKeyType.Xml | RsaKeyType.Public));
    }

    [Theory]
    [InlineData(TestRSAKeys.XmlPublicKey_2, TestRSAKeys.Pkcs8PublicKey_2)]
    [InlineData(TestRSAKeys.XmlPublicKey_3, TestRSAKeys.Pkcs8PublicKey_3)]
    [InlineData(TestRSAKeys.XmlPublicKey_4, TestRSAKeys.Pkcs8PublicKey_4)]
    [InlineData(TestRSAKeys.XmlPublicKey_5, TestRSAKeys.Pkcs8PublicKey_5)]
    public void Format_Public_XmlToPkcs8(string input, string expected)
    {
        Assert.Equal(expected.ReplaceLineEndings(), RsaKeyConvert.Format(input, RsaKeyType.Xml | RsaKeyType.Public, RsaKeyType.Pkcs8 | RsaKeyType.Public));
    }
}