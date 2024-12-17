using System.Security.Cryptography;

namespace KeyServiceProvider
{
    public class KeyServiceProviderCLI
    {
        static async Task Main()
        {
            Console.WriteLine("Welcome to the Secure File Encryption/Decryption Application!");
            while (true) //loop for continuous menu access
            {
                DisplayMenu();
                string userOption = Console.ReadLine();

                if (userOption == "1") //option 1: encrypt a file
                {
                    Console.WriteLine("Please specify the path to your file: ");
                    string absFilePath = Console.ReadLine();
                    string checker = CheckFilePath(absFilePath);

                    if (checker == null) //filepath not valid
                    {
                        Console.WriteLine("Invalid file path. Returning to the main menu...");
                        continue;
                    }
                    else
                    {
                        Console.WriteLine("File path is valid. Reading the file...");
                        try
                        {
                            byte[] fileData = await ReadFileAsync(absFilePath);
                            Console.WriteLine("File is valid. Proceeding with encryption...");
                            string directory = Path.GetDirectoryName(absFilePath);
                            await EncryptFileAsync(fileData, directory);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error reading file: {ex.Message}");
                        }
                    }
                }
                else if (userOption == "2") //option 2: decrypt a file
                {
                    try
                    {
                        await DecryptFileAsync();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error reading file: {ex.Message}");
                    }
                }
                else if (userOption == "3") //option 3: check quantum resilience of RSA key
                {
                    CheckRSAQuantumResilience();
                }
                else if (userOption == "4") //option 4: exit program
                {
                    Console.WriteLine("Exiting the application. Goodbye!");
                    break; //exit the program
                }
                else
                {
                    Console.WriteLine("Invalid option. Please choose an option from the menu below.");
                    continue; //display the menu again
                }

                Console.WriteLine("Do you want to perform another operation? (y/n)"); //ask after every operation
                string choice = Console.ReadLine()?.ToLower();
                if (choice == "n")
                {
                    Console.WriteLine("Exiting the application. Goodbye!");
                    break; //exit the program
                }
            }
        }

        //menu
        static void DisplayMenu()
        {
            Console.WriteLine("Choose an option to continue...");
            Console.WriteLine("1: Encrypt a file");
            Console.WriteLine("2: Decrypt a file");
            Console.WriteLine("3: Check Quantum Resilience of RSA private key");
            Console.WriteLine("4: Exit the program");
        }

        //file path validity check
        static string CheckFilePath(string absFilePath)
        {
            if (string.IsNullOrEmpty(absFilePath))
            {
                Console.WriteLine("File path cannot be empty.");
                return null;
            }

            if (absFilePath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                Console.WriteLine("File path contains invalid characters.");
                return null;
            }

            if (!File.Exists(absFilePath))
            {
                Console.WriteLine("File does not exist.");
                return null;
            }

            return absFilePath;
        }

        //asynchonous method for reading files
        static async Task<byte[]> ReadFileAsync(string filePath)
        {
            return await File.ReadAllBytesAsync(filePath);
        }

        //asynchonous method for writing files
        static async Task WriteFileAsync(string filePath, byte[] data)
        {
            await File.WriteAllBytesAsync(filePath, data);
        }

        //ENCRYPTION
        //encrypts user-given file using AES for the data encryption
        //RSA key is used to encrypt the AES key
        //HMAC (Hash-based Message Authentication Code) is generated to ensure data integrity
        static async Task EncryptFileAsync(byte[] fileBytes, string directory)
        {
            //generate and export RSA public and private keys
            using RSA rsa = RSA.Create(2048);
            string publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
            string privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

            //generate AES key
            using Aes aes = Aes.Create();
            aes.GenerateKey();

            //encrypt the file using AES
            //TransformFinalBlock encrypts the provided data using the AES key where it processes the entire data at once and returns the encrypted output
            using var encryptor = aes.CreateEncryptor();
            byte[] encryptedFile = encryptor.TransformFinalBlock(fileBytes, 0, fileBytes.Length);

            //encrypt AES key with RSA public key
            //OAEP with SHA-256 padding ensures that only the RSA private key can decrypt it 
            //it adds randomness to the encryption process to prevent attacks like padding oracle attacks (more secure than the older PKCS1 padding)
            byte[] encryptedAESKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);

             //generate HMAC for data integrity
            byte[] computedHMAC = ComputeHMAC(fileBytes, aes.Key);

            //save all components with unique names
            string timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            await WriteFileAsync(Path.Combine(directory, $"EncryptedFile_{timestamp}.bin"), encryptedFile);
            await WriteFileAsync(Path.Combine(directory, $"EncryptedAESKey_{timestamp}.bin"), encryptedAESKey);
            await WriteFileAsync(Path.Combine(directory, $"FileHMAC_{timestamp}.bin"), computedHMAC);
            await File.WriteAllTextAsync(Path.Combine(directory, $"PrivateKey_{timestamp}.txt"), privateKey);

            Console.WriteLine($"Encryption complete. Files saved in the same directory: {directory}");
        }

        //DECRYPTION
        //provided RSA private key decrypts the encrypted file
        //then AES key decrypts the data
        //HMAC validation ensures that the file's integrity has not been compromised
        static async Task DecryptFileAsync()
        {
            try
            {
                //get user inputs for file paths
                Console.WriteLine("Enter the path of the encrypted file:");
                string encryptedFilePath = CheckFilePath(Console.ReadLine());

                Console.WriteLine("Enter the path of the AES key file:");
                string encryptedKeyPath = CheckFilePath(Console.ReadLine());

                Console.WriteLine("Enter the path of the HMAC file (or press Enter to skip):");
                string hmacPath = Console.ReadLine();

                Console.WriteLine("Enter the path of your private RSA key file:");
                string privateKeyPath = CheckFilePath(Console.ReadLine());

               //validate file existence
                if (encryptedFilePath == null || encryptedKeyPath == null || privateKeyPath == null)
                {
                    Console.WriteLine("One or more required file paths are invalid.");
                    return;
                }

                //load files
                byte[] encryptedData = await ReadFileAsync(encryptedFilePath);
                byte[] encryptedAesKey = await ReadFileAsync(encryptedKeyPath);
                byte[] privateKey = Convert.FromBase64String(await File.ReadAllTextAsync(privateKeyPath));

                //decrypt the AES key using RSA priv key
                using RSA rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(privateKey, out _);
                byte[] aesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);

                //HMAC validaton (if provided)
                if (!string.IsNullOrWhiteSpace(hmacPath))
                {
                    if (!File.Exists(hmacPath))
                    {
                        Console.WriteLine("HMAC file path is invalid. Decryption stopped.");
                        return;
                    }

                    byte[] providedHmac = await ReadFileAsync(hmacPath);
                    byte[] computedHmac = ComputeHMAC(encryptedData, aesKey);

                    if (!providedHmac.SequenceEqual(computedHmac))
                    {
                        Console.WriteLine("HMAC validation failed. File integrity compromised. Decryption stopped.");
                        return;
                    }

                    Console.WriteLine("HMAC validation succeeded. Proceeding with decryption...");
                }
                else
                {
                    Console.WriteLine("No HMAC file provided. Proceeding with decryption at your own risk.");
                }

                //decrypt the file using AES
                using Aes aes = Aes.Create();
                aes.Key = aesKey;

                //data is treated as a stream and the AES decryptor is applied
                //new memory stream is initialised and decrypted data is asynchronously written to it
                using MemoryStream ms = new MemoryStream(encryptedData);
                using CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
                using MemoryStream output = new MemoryStream();
                await cs.CopyToAsync(output);

                byte[] decryptedData = output.ToArray();

                string outputPath = encryptedFilePath.Replace(".bin", "_decrypted.txt");
                await WriteFileAsync(outputPath, decryptedData);

                Console.WriteLine($"Decryption successful! File saved at: {outputPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during decryption: {ex.Message}");
            }
        }

        //HMAC computation
        static byte[] ComputeHMAC(byte[] data, byte[] aesKey)
        {
            using HMACSHA256 hmac = new HMACSHA256(aesKey);
            return hmac.ComputeHash(data);
        }

        //QUANTUM RESILIENCE
        //checks if the RSA private key is resilient to quantum computing by verifying its size
        //RSA keys below 2048 bits are considered vulnerable
        static void CheckRSAQuantumResilience()
        {
            //get user input of the RSA private key
            Console.WriteLine("Enter the path of the RSA private key you want to check: ");
            string keyPath = Console.ReadLine();
            byte[] key = Convert.FromBase64String(File.ReadAllText(keyPath));

            //define RSA's quantum-resilient threshold
            int rsaThreshold = 2048;

            try
            {
                //check for RSA private key
                using RSA rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(key, out _);

                //check for RSA key resilience
                if (key.Length < rsaThreshold)
                {
                    Console.WriteLine($"WARNING: RSA key size of {key.Length} bits is vulnerable to quantum attacks. Consider using at least RSA 2048.");
                }
                else
                {
                    Console.WriteLine("Your AES key is quantum safe.");
                }
            }
            catch
            {
                Console.WriteLine("File is not a RSA private key");
            }
        }
    }
}

