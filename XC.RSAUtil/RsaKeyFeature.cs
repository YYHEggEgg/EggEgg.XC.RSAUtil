using System;
using System.Collections.Generic;

namespace XC.RSAUtil
{
    public enum RsaKeyPadding
    {
        Invalid,
        Xml,
        Pkcs1,
        Pkcs8,
    }

    public enum RsaKeyFormat
    {
        Invalid,
        Xml,
        Pem,
        Der,
    }

    public class RsaKeyFeature : IEquatable<RsaKeyFeature?>
    {
        public bool IsPrivate;
        public RsaKeyPadding Padding;
        public RsaKeyFormat Format;

        public RsaKeyFeature DeepClone() => new RsaKeyFeature
        {
            IsPrivate = IsPrivate,
            Padding = Padding,
            Format = Format,
        };

        public override bool Equals(object? obj)
        {
            return Equals(obj as RsaKeyFeature);
        }

        public bool Equals(RsaKeyFeature? other)
        {
            return !(other is null) &&
                   IsPrivate == other.IsPrivate &&
                   Padding == other.Padding &&
                   Format == other.Format;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(IsPrivate, Padding, Format);
        }

        public static bool operator ==(RsaKeyFeature? left, RsaKeyFeature? right)
        {
            if (left is null) return right is null;
            return left.Equals(right);
        }

        public static bool operator !=(RsaKeyFeature? left, RsaKeyFeature? right)
        {
            return !(left == right);
        }
    }
}
