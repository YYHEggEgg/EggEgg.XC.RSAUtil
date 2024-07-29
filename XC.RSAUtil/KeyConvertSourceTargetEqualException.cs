using System;

namespace XC.RSAUtil
{
    internal class KeyConvertSourceTargetEqualException : Exception
    {
        public KeyConvertSourceTargetEqualException()
            : base("Input and output key cannot be the same padding and format when input and output are both private/public keys.")
        {
        }
    }
}