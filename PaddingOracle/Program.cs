using System.Security.Cryptography;
using System.Text;

namespace PaddingOracle;

class PaddingOracle
{
    public delegate bool CheckPadding(byte[] cipher);
    private readonly CheckPadding isValid;
    private readonly int block_size;
    private readonly List<byte[]> blocks;
    public PaddingOracle(CheckPadding paddingValid, byte[] cipherText, int blockSize = 16)
    {
        isValid = paddingValid;
        block_size = blockSize;
        blocks = LoadBlocks(cipherText); // Separate the blocks from each other
    }

    private List<byte[]> LoadBlocks(byte[] cipher)
    {
        var blockList = new List<byte[]>();
        for (int i = 0; i < cipher.Length; i += block_size)
        {
            var tmp = new byte[block_size];
            Array.Copy(cipher, i, tmp, 0, block_size);
            blockList.Add(tmp);
        }

        return blockList;
    }

    private byte[] PackList(List<byte[]> list)
    {
        var finalResult = new byte[0];

        for (int i = 0; i < list.Count; i++)
        {
            var subResult = list[i];
            var tmp = new byte[finalResult.Length];
            Array.Copy(finalResult, tmp, finalResult.Length);
            finalResult = new byte[tmp.Length + subResult.Length];
            Array.Copy(tmp, finalResult, tmp.Length);
            Array.Copy(subResult, 0, finalResult, tmp.Length, subResult.Length);
        }

        return finalResult;
    }

    public (byte[] firstBlock, byte[] decryptedBlocks) Decrypt()
    {
        var results = new List<byte[]>();

        for (int i = 0; i < blocks.Count; i++)
        {
            if (i + 1 == blocks.Count)
                break;

            var subResult = _decrypt(blocks[i], blocks[i + 1]);
            results.Add(subResult);
        }

        // Return first block because it's protected by the IV
        // which might be unknown, and thus can't be decrypted
        return (blocks[0], PackList(results));
    }

    // 'decrypt' - LOL, more like brute force in real time
    private byte[] _decrypt(byte[] firstBlock, byte[] secondBlock)
    {
        byte[] decrypted = new byte[block_size];

        // Try all possible padding values
        for (int t = 0; t < block_size; t++)
        {
            // Padding is never 0, but it can be 16 when an entire block is just padding
            int padding = t + 1;
            byte[] emulated = new byte[block_size];
            if (decrypted[block_size - 1] != 0)
            {
                for (int i = 0; i < block_size; i++)
                {
                    if (decrypted[i] == 0)
                        continue;

                    emulated[i] = (byte)(padding ^ decrypted[i] ^ firstBlock[i]);
                }
            }
            byte[] cipher = new byte[block_size * 2];
            Array.Copy(emulated, cipher, block_size);
            Array.Copy(secondBlock, 0, cipher, block_size, block_size);
            int validByte = -1;

            // Brute force the proper value to get the desired padding value
            // This is the root of the attack
            for (int i = 0; i < 255; i++)
            {
                cipher[cipher.Length - padding - block_size] = (byte)i;
                if (isValid(cipher))
                {
                    validByte = i;
                    break;
                }
            }

            int plainText = padding ^ firstBlock[block_size - padding] ^ validByte;
            decrypted[block_size - padding] = (byte)plainText;
        }

        int dataLength = block_size - decrypted[block_size - 1];
        if (dataLength > 0)
        {
            byte[] removePadding = new byte[dataLength];
            Array.Copy(decrypted, removePadding, dataLength);
            return removePadding;
        }
        else return decrypted;
    }
}
class Program
{
    static private readonly byte[] _iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    static private readonly byte[] _key = Encoding.ASCII.GetBytes("Sshh!SecretKey42");
    static byte[] GetEncryptedBytes(string plaintext)
    {
        if (plaintext is null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }

        byte[] encrypted;

        using Aes aes = Aes.Create();
        aes.IV = _iv;
        aes.Key = _key;
        aes.Padding = PaddingMode.PKCS7;
        aes.Mode = CipherMode.CBC;

        ICryptoTransform encryptor = aes.CreateEncryptor();

        using MemoryStream msEncrypt = new MemoryStream();
        using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using StreamWriter swEncrypt = new StreamWriter(csEncrypt);

        swEncrypt.Write(plaintext);
        swEncrypt.Flush();
        csEncrypt.FlushFinalBlock();

        encrypted = msEncrypt.ToArray();

        return encrypted;
    }

    static string GetDecryptedBytes(byte[] cipherText)
    {
        if (cipherText is null)
        {
            throw new ArgumentNullException(nameof(cipherText));
        }

        string plaintext;

        using Aes aes = Aes.Create();
        aes.IV = _iv;
        aes.Key = _key;
        aes.Padding = PaddingMode.PKCS7;
        aes.Mode = CipherMode.CBC;

        ICryptoTransform decryptor = aes.CreateDecryptor();

        using MemoryStream msDecrypt = new MemoryStream(cipherText);
        using CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using StreamReader srDecrypt = new StreamReader(csDecrypt);

        plaintext = srDecrypt.ReadToEnd();

        return plaintext;
    }

    static void Main(string[] args)
    {
        byte[] ciphertext = GetEncryptedBytes("Today's secret message is: Attack at dawn, on the northern beachhead.");

        bool paddingChecker(byte[] cipher)
        {
            try
            {
                GetDecryptedBytes(cipher);
                return true;
            }
            catch (CryptographicException ex)
            {
                return ex.Message == "Padding is invalid and cannot be removed." ? false : true;
            }
        }

        // mount the attack
        var po = new PaddingOracle(paddingChecker, ciphertext, 16);
        (byte[] n, byte[] naughty) = po.Decrypt();
        Console.WriteLine("Msg: " + Encoding.ASCII.GetString(naughty));
    }
}