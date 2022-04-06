using System;
using System.Security.Cryptography;
using System.Text;

namespace OAuth2.PKCE.Client;

/// <summary>
/// Generates pseudorandom keys
/// </summary>
public static class KeyGenerator
{
    private static readonly char[] CharacterSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

    /// <summary>
    /// Creates a pseudorandom string of a desired length
    /// </summary>
    /// <param name="size">Desired ength of the string</param>
    /// <returns>Random string</returns>
    public static string Random(int size)
    {
        byte[] data = new byte[4 * size];
        using var crypto = RandomNumberGenerator.Create();
        {
            crypto.GetBytes(data);
        }

        var result = new StringBuilder(size);

        for (int i = 0; i < size; i++)
        {
            var random = BitConverter.ToUInt32(data, i * 4);
            var index = random % CharacterSet.Length;

            result.Append(CharacterSet[index]);
        }

        return result.ToString();
    }
}