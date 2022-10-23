using System.Security.Cryptography;
using System.Text;

namespace Aes_Example
{
    class AesExample
    {
        private static byte[] _solt = { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 };
        private static int _iterations = 128;
        private static HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;

        public static void Main()
        {
            string? option;
            do
            {
                Console.WriteLine("1. Select for Encryption.");
                Console.WriteLine("2. Select for  Decryption.");
                Console.WriteLine("0. Select for Exit.");

                option = Console.ReadLine()?.ToString();

                string? userTextInput = null;
                string? userKey = null;

                if (option == "1")
                {
                    Console.WriteLine("Enter your text:");
                    userTextInput = Console.ReadLine()?.ToString();
                }
                else if (option == "2")
                {
                    Console.WriteLine("Enter your decrypt text");
                    userTextInput = Console.ReadLine()?.ToString();
                }

                if (option != "0")
                {
                    Console.WriteLine("enter your key:");
                    userKey = Console.ReadLine()?.ToString();


                }

                if (userTextInput != null && userKey != null)
                {
                    if (option == "1")
                    {
                        string encryptText = Encrypt(userTextInput, userKey, _solt, _iterations, _hashAlgorithm);
                        Console.WriteLine("Plane Text: {0}", encryptText);
                    }
                    else if (option == "2")
                    {
                        string decryptText = Decrypt(userTextInput, userKey, _solt, _iterations, _hashAlgorithm);

                        if (decryptText == "error")
                            Console.WriteLine("Enter correct paaword or cipher text.");
                        else
                            Console.WriteLine("Decrypt Text: {0}", decryptText);
                    }
                }
            }
            while (option != "0");

        }

        static string Encrypt(string clearText, string key, byte[] salt, int iteration, HashAlgorithmName hasAlgorithonName)
        {
            string encryptionKey = key;
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, salt, iteration, hasAlgorithonName);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }

        static string Decrypt(string cipherText, string key, byte[] salt, int iteration, HashAlgorithmName hasAlgorithonName)
        {
            string encryptionKey = key;
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(encryptionKey, salt, iteration, hasAlgorithonName);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        try
                        {
                            cs.Write(cipherBytes, 0, cipherBytes.Length);
                            cs.Close();
                        }
                        catch (Exception ex)
                        {
                            if (ex != null)
                                cipherText = "error";
                        }
                    }
                    if (cipherText != "error")
                        cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }
    }
}