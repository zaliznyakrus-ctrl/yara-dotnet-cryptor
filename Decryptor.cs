using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

class Decryptor
{
    private static byte[] RC4(byte[] data, byte[] key)
    {
        byte[] s = new byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) % 256;
            (s[i], s[j]) = (s[j], s[i]);
        }

        byte[] result = new byte[data.Length];
        int a = 0, b = 0;
        for (int x = 0; x < data.Length; x++)
        {
            a = (a + 1) % 256;
            b = (b + s[a]) % 256;
            (s[a], s[b]) = (s[b], s[a]);
            result[x] = (byte)(data[x] ^ s[(s[a] + s[b]) % 256] ^ key[x % key.Length]);
        }
        return result;
    }

    static byte[]? ExtractFromBundle(byte[] data, string targetName)
    {
        byte prefixLen = (byte)targetName.Length;
        byte[] needle = new byte[1 + prefixLen];
        needle[0] = prefixLen;
        Encoding.ASCII.GetBytes(targetName, 0, targetName.Length, needle, 1);

        for (int i = data.Length - 1; i >= 25; i--)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (data[i + j] != needle[j]) { match = false; break; }
                if (i + j >= data.Length) { match = false; break; }
            }
            if (!match) continue;

            long offset, size;
            if (i >= 25)
            {
                offset = BitConverter.ToInt64(data, i - 25);
                size = BitConverter.ToInt64(data, i - 17);
                long compressed = BitConverter.ToInt64(data, i - 9);
                byte fileType = data[i - 1];

                if (offset > 0 && offset < data.Length && size > 0 && size < data.Length &&
                    offset + size <= data.Length && fileType <= 10)
                {
                    Console.WriteLine($"[+] Found '{targetName}' at offset 0x{offset:X}, size {size:N0} bytes (type={fileType})");
                    byte[] result = new byte[size];
                    Array.Copy(data, offset, result, 0, (int)size);

                    if (result.Length >= 2 && result[0] == 0x4D && result[1] == 0x5A)
                        return result;
                }
            }

            if (i >= 17)
            {
                offset = BitConverter.ToInt64(data, i - 17);
                size = BitConverter.ToInt64(data, i - 9);
                byte fileType = data[i - 1];

                if (offset > 0 && offset < data.Length && size > 0 && size < data.Length &&
                    offset + size <= data.Length && fileType <= 10)
                {
                    Console.WriteLine($"[+] Found '{targetName}' at offset 0x{offset:X}, size {size:N0} bytes (type={fileType})");
                    byte[] result = new byte[size];
                    Array.Copy(data, offset, result, 0, (int)size);

                    if (result.Length >= 2 && result[0] == 0x4D && result[1] == 0x5A)
                        return result;
                }
            }
        }
        return null;
    }

    static byte[]? ExtractKey(byte[] rawBytes)
    {
        try
        {
            var asm = Assembly.Load(rawBytes);
            var privImpl = asm.GetTypes().FirstOrDefault(t => t.Name.Contains("<PrivateImplementationDetails>"));
            if (privImpl != null)
            {
                foreach (var field in privImpl.GetFields(BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Public))
                {
                    try
                    {
                        if (field.FieldType.IsValueType && Marshal.SizeOf(field.FieldType) == 16)
                        {
                            byte[] key = new byte[16];
                            RuntimeHelpers.InitializeArray(key, field.FieldHandle);
                            Console.WriteLine($"[+] RC4 key (via InitializeArray): [{string.Join(", ", key)}]");
                            return key;
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        for (int i = 0; i < rawBytes.Length - 200; i++)
        {
            bool isLdc16 = (rawBytes[i] == 0x1F && rawBytes[i + 1] == 0x10) ||
                           (rawBytes[i] == 0x20 && rawBytes[i + 1] == 0x10 &&
                            rawBytes[i + 2] == 0x00 && rawBytes[i + 3] == 0x00 && rawBytes[i + 4] == 0x00);
            if (!isLdc16) continue;

            int newarrPos = rawBytes[i] == 0x1F ? i + 2 : i + 5;
            if (newarrPos >= rawBytes.Length - 1 || rawBytes[newarrPos] != 0x8D) continue;

            int searchStart = newarrPos + 5;
            byte[] key = new byte[16];
            int found = 0;

            for (int p = searchStart; p < Math.Min(searchStart + 300, rawBytes.Length - 5) && found < 16; p++)
            {
                if (rawBytes[p] == 0x1F && p + 2 < rawBytes.Length)
                {
                    for (int look = p + 2; look < Math.Min(p + 6, rawBytes.Length); look++)
                        if (rawBytes[look] == 0x9C) { key[found++] = rawBytes[p + 1]; p = look; break; }
                }
                else if (rawBytes[p] == 0x20 && p + 5 < rawBytes.Length &&
                         rawBytes[p + 2] == 0x00 && rawBytes[p + 3] == 0x00 && rawBytes[p + 4] == 0x00)
                {
                    for (int look = p + 5; look < Math.Min(p + 8, rawBytes.Length); look++)
                        if (rawBytes[look] == 0x9C) { key[found++] = rawBytes[p + 1]; p = look; break; }
                }
            }

            if (found == 16)
            {
                Console.WriteLine($"[+] RC4 key (via stelem): [{string.Join(", ", key)}]");
                return key;
            }
        }
        return null;
    }

    static byte[]? ExtractResource(byte[] dllBytes)
    {
        try
        {
            Assembly asm = Assembly.Load(dllBytes);
            string[] resources = asm.GetManifestResourceNames();
            Console.WriteLine($"[*] Resources: [{string.Join(", ", resources)}]");

            string? resName = resources.FirstOrDefault(r => r == "r") ?? resources.FirstOrDefault();
            if (resName == null) return null;

            using Stream? stream = asm.GetManifestResourceStream(resName);
            if (stream == null) return null;

            byte[] data = new byte[stream.Length];
            stream.Read(data, 0, data.Length);
            Console.WriteLine($"[+] Resource '{resName}' extracted: {data.Length:N0} bytes");
            return data;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Assembly.Load failed: {ex.Message}");
            return null;
        }
    }

    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length < 1)
        {
            Console.WriteLine();
            Console.WriteLine("  RC4+XOR .NET Crypter Decryptor");
            Console.WriteLine("  ==============================");
            Console.WriteLine();
            Console.WriteLine("  Usage: decryptor.exe <crypter.exe>");
            Console.WriteLine();
            Console.WriteLine("  Supports:");
            Console.WriteLine("    - .NET Core single-file bundle (25-45 MB)");
            Console.WriteLine("    - Standalone p.dll");
            Console.WriteLine("    - Raw encrypted payload");
            Console.WriteLine();
            Console.WriteLine("  Output: decrypted.exe (same folder as decryptor)");
            Console.WriteLine();
            return;
        }

        try
        {
            string inputPath = Path.GetFullPath(args[0]);
            string outputDir = AppDomain.CurrentDomain.BaseDirectory;
            string outputPath = Path.Combine(outputDir, "decrypted.exe");

            byte[] fileData = File.ReadAllBytes(inputPath);
            Console.WriteLine($"[*] Input: {inputPath} ({fileData.Length:N0} bytes)");

            byte[]? dllBytes = null;
            byte[]? encrypted = null;
            byte[]? key = null;

            if (fileData.Length > 5_000_000)
            {
                Console.WriteLine("[*] Large file detected, parsing as .NET Core bundle...");
                dllBytes = ExtractFromBundle(fileData, "p.dll");

                if (dllBytes != null)
                {
                    Console.WriteLine($"[+] p.dll extracted from bundle: {dllBytes.Length:N0} bytes");
                }
                else
                {
                    Console.WriteLine("[!] Bundle signature not found or p.dll missing");
                }
            }

            if (dllBytes == null)
            {
                Console.WriteLine("[*] Treating input as standalone assembly...");
                dllBytes = fileData;
            }

            encrypted = ExtractResource(dllBytes);
            if (encrypted == null)
            {
                Console.WriteLine("[!] No resource found, treating as raw encrypted data");
                encrypted = dllBytes;
            }

            key = ExtractKey(dllBytes);
            if (key == null)
            {
                Console.WriteLine("[!] Key not found, using hardcoded default");
                key = new byte[] { 86, 28, 72, 236, 229, 199, 30, 73,
                                   133, 186, 253, 100, 137, 66, 202, 204 };
            }

            Console.WriteLine($"[*] Decrypting {encrypted.Length:N0} bytes...");
            byte[] decrypted = RC4(encrypted, key);
            File.WriteAllBytes(outputPath, decrypted);

            Console.WriteLine($"[+] Saved: {outputPath}");
            Console.WriteLine($"[+] Size:  {decrypted.Length:N0} bytes");

            if (decrypted.Length >= 2 && decrypted[0] == 0x4D && decrypted[1] == 0x5A)
                Console.WriteLine("[+] PE header detected (MZ)");
            else
                Console.WriteLine("[!] Output does not look like a PE file");

            Console.WriteLine();
            Console.WriteLine("[+] Done.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[-] Error: {ex.Message}");
        }
    }
}
