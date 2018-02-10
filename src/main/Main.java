package main;

import java.io.UnsupportedEncodingException;

import java.math.BigInteger;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * This program simulates a Diffie-Hellman key exchange
 * protocol. Available commands are displayed at the
 * program start. Due to UTF-8 encoding used, the console
 * may fail to display the user prompt correctly. This is
 * a visual glitch and has nothing to do with the program
 * itself. Typing in to the console will fix the prompt.
 * 
 * @author Kaan Yıldırım - <a href="mailto:kyildirim14@ku.edu.tr">kyildirim14@ku.edu.tr</a>
 * @version 1.1b
 */
class Main {

	/**
	 * Prime value used.
	 * @see #generatePrime(int)
	 */
	private static BigInteger prime;
	
	/**
	 * Generator value used.
	 * @see #generateGenerator(BigInteger)
	 */
	private static BigInteger generator;
	
	/**
	 * Secret of Alice.
	 * @see #init()
	 */
	private static BigInteger secretAlice;
	
	/**
	 * Secret of Bob.
	 * @see #init()
	 */
	private static BigInteger secretBob;
	
	/**
	 * Public of Alice.
	 * @see #init()
	 */
	private static BigInteger publicAlice;
	
	/**
	 * Public of Bob.
	 * @see #init()
	 */
	private static BigInteger publicBob;
	
	/**
	 * Shared key between Alice and Bob.
	 * @see #init()
	 * @see #cipherEncryptAliceEve
	 * @see #cipherDecryptAliceEve
	 */
	private static BigInteger sharedKeyAliceBob;
	
	/**
	 * Secret of Eve.
	 * @see #init()
	 */
	private static BigInteger secretEve;
	
	/**
	 * Public of Eve.
	 * @see #init()
	 */
	private static BigInteger publicEve;
	
	/**
	 * Shared key between Alice and Eve.
	 * @see #init()
	 * @see #cipherEncryptAliceEve
	 * @see #cipherDecryptAliceEve
	 */
	private static BigInteger sharedKeyAliceEve;
	
	/**
	 * Shared key between Bob and Eve.
	 * @see #init()
	 * @see #cipherEncryptBobEve
	 * @see #cipherDecryptBobEve
	 */
	private static BigInteger sharedKeyBobEve;
	
	
	/**
	 * Message digest algorithm used. Initialized as SHA-256. 
	 */
	private static MessageDigest messageDigest;

	/**
	 * Cipher running in encryption mode with the key of Alice and Bob.
	 * @see #sharedKeyAliceBob
	 * @see #cipherDecryptAliceBob
	 */
	private static Cipher cipherEncrypAliceBob;
	
	/**
	 * Cipher running in encryption mode with the key of Alice and Eve.
	 * @see #sharedKeyAliceEve
	 * @see #cipherDecryptAliceEve
	 */
	private static Cipher cipherEncryptAliceEve;
	
	/**
	 * Cipher running in encryption mode with the key of Bob and Eve.
	 * @see #sharedKeyBobEve
	 * @see #cipherDecryptBobEve
	 */
	private static Cipher cipherEncryptBobEve;

	
	/**
	 * Cipher running in decryption mode with the key of Alice and Bob.
	 * @see #sharedKeyAliceBob
	 * @see #cipherEncrypAliceBob
	 */
	private static Cipher cipherDecryptAliceBob;
	
	/**
	 * Cipher running in decryption mode with the key of Alice and Eve.
	 * @see #sharedKeyAliceEve
	 * @see #cipherEncryptAliceEve
	 */
	private static Cipher cipherDecryptAliceEve;
	
	/**
	 * Cipher running in decryption mode with the key of Bob and Eve.
	 * @see #sharedKeyBobEve
	 * @see #cipherEncryptBobEve
	 */
	private static Cipher cipherDecryptBobEve;
	
	/**
	 * MITM mode flag.
	 */
	private static boolean mitm = false;

	public static void main(String args[]) {

		//Display help message.
		help();
		
		// Initialize the key exchange.
		init();

		// Scanner to scan System.in for user input.
		Scanner sc = new Scanner(System.in);
		// Variable to hold scanned inputs.
		String msg = "";
		// Current user.
		String username = "Alice";
		// Byte array for storing ciphertexts.
		byte[] cip = null;
		// Byte array for storing plaintexts.
		byte[] pla = null;

		// Main chat loop.
		while (true) {
			if (mitm) {
				// Display current user before asking for input.
				System.out.print(username + ": ");
				// Read input from user.
				msg = sc.nextLine();
				// Address help request if available.
				if(msg.toLowerCase().equals("help")){
					// Display the help message.
					help();
					// Display current user before asking for input.
					System.out.print(username + ": ");
					// Ask for actual input after help.
					msg = sc.nextLine();
				}
				// Address renew request if available.
				if (msg.toLowerCase().equals("renew")) {
					// Announce renewal request.
					System.out.println(username + " requested a key renewal.");
					// Re-initialize the key exchange.
					init();
					// Announce renewal.
					System.out.println("Keys renewed on " + username + "'s request.");
					// Display current user before asking for input.
					System.out.print(username + ": ");
					// Ask for actual input after renewal.
					msg = sc.nextLine();
				}
				// Switch to MITM mode.
				if (msg.toLowerCase().equals("mitm")) {
					// Activate MITM mode.
					mitm = false;
					// Announce deactivation.
					System.out.println(username + " deactivated the MITM mode.");
					System.out.println("Communications will no longer be relayed over Eve.");
					// Ask to renew the keys.
					System.out.print("[System] Would you like to renew the keys? (y/n): ");
					msg = sc.nextLine();
					if (msg.toLowerCase().startsWith("y")) {
						// Announce renewal request.
						System.out.println(username + " requested a key renewal.");
						// Re-initialize the key exchange.
						init();
						// Announce renewal.
						System.out.println("Keys renewed on " + username + "'s request.");
					}
					continue;
				}
				// Exit on given matches.
				if (msg.toLowerCase().equals("exit") || msg.toLowerCase().equals("quit") || msg.equals(""))
					break;
				// Encrypt the given input.
				try {
					cip = cipherEncryptAliceEve.doFinal(msg.getBytes("UTF-8"));
				} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				// Display the resulting ciphertext from encryption.
				System.out.println("Ciphertext from " + username + ": " + new String(cip));
				// Decrypt the given ciphertext.
				try {
					pla = cipherDecryptAliceEve.doFinal(cip);
				} catch (IllegalBlockSizeException | BadPaddingException e) {
					e.printStackTrace();
				}
				// Display the resulting plaintext from decryption.
				System.out.println("Plaintext to Eve: " + new String(pla));
				// Encrypt the given input.
				try {
					cip = cipherEncryptBobEve.doFinal(msg.getBytes("UTF-8"));
				} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				// Display the resulting ciphertext from encryption.
				System.out.println("Ciphertext from Eve: " + new String(cip));
				// Decrypt the given ciphertext.
				try {
					pla = cipherDecryptBobEve.doFinal(cip);
				} catch (IllegalBlockSizeException | BadPaddingException e) {
					e.printStackTrace();
				}
				// Change user.
				username = username.equals("Alice") ? "Bob" : "Alice";
				// Display the resulting plaintext from decryption.
				System.out.println("Plaintext to " + username + ": " + new String(pla));
			} else {
				// Display current user before asking for input.
				System.out.print(username + ": ");
				// Read input from user.
				msg = sc.nextLine();
				// Address help request if available.
				if(msg.toLowerCase().equals("help")){
					// Display the help message.
					help();
					// Display current user before asking for input.
					System.out.print(username + ": ");
					// Ask for actual input after help.
					msg = sc.nextLine();
				}
				// Address renew request if available.
				if (msg.toLowerCase().equals("renew")) {
					// Announce renewal request.
					System.out.println(username + " requested a key renewal.");
					// Re-initialize the key exchange.
					init();
					// Announce renewal.
					System.out.println("Keys renewed on " + username + "'s request.");
					// Display current user before asking for input.
					System.out.print(username + ": ");
					// Ask for actual input after renewal.
					msg = sc.nextLine();
				}
				// Switch to MITM mode.
				if (msg.toLowerCase().equals("mitm")) {
					// Activate MITM mode.
					mitm = true;
					// Announce activation.
					System.out.println(username + " activated the MITM mode.");
					System.out.println("Communications will be relayed over Eve.");
					// Ask to renew the keys.
					System.out.print("[System] Would you like to renew the keys? (y/n): ");
					msg = sc.nextLine();
					if (msg.toLowerCase().startsWith("y")) {
						// Announce renewal request.
						System.out.println(username + " requested a key renewal.");
						// Re-initialize the key exchange.
						init();
						// Announce renewal.
						System.out.println("Keys renewed on " + username + "'s request.");
					}
					continue;
				}
				// Exit on given matches.
				if (msg.toLowerCase().equals("exit") || msg.toLowerCase().equals("quit") || msg.equals(""))
					break;
				// Encrypt the given input.
				try {
					cip = cipherEncrypAliceBob.doFinal(msg.getBytes("UTF-8"));
				} catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				// Display the resulting ciphertext from encryption.
				System.out.println("Ciphertext: " + new String(cip));
				// Decrypt the given ciphertext.
				try {
					pla = cipherDecryptAliceBob.doFinal(cip);
				} catch (IllegalBlockSizeException | BadPaddingException e) {
					e.printStackTrace();
				}
				// Display the resulting plaintext from decryption.
				System.out.println("Plaintext: " + new String(pla));
				// Change user.
				username = username.equals("Alice") ? "Bob" : "Alice";
			}
		}

		// Close the scanner scanning the System.in
		sc.close();
	}

	/**
	 * Initializes the keys and the ciphers to be used. Keys are generated in the bit length of {@value #KEY_LENGTH}. Ciphers are AES.
	 * @see #KEY_LENGTH
	 * @since 1.0b
	 */
	private static void init() {

		// Empty separator line.
		System.out.println();
		
		// BigInteger value for shared key.
		sharedKeyAliceBob = new BigInteger("0");
		// BigInteger for the prime used.
		prime = generatePrime(KEY_LENGTH);
		// Print the selected prime.
		System.out.println("Prime: " + prime.toString());
		// Generator for the prime.
		generator = generateGenerator(prime);
		// Print the generator.
		System.out.println("Generator: " + generator.toString());

		// Secrets
		secretAlice = new BigInteger(KEY_LENGTH - 16, new SecureRandom());
		System.out.println("Secret A: " + secretAlice.toString());
		secretBob = new BigInteger(KEY_LENGTH - 16, new SecureRandom());
		System.out.println("Secret B: " + secretBob.toString());
		secretEve = new BigInteger(KEY_LENGTH - 16, new SecureRandom());
		System.out.println("Secret E: " + secretEve.toString());

		// Publics
		publicAlice = generator.modPow(secretAlice, prime);
		System.out.println("Public A: " + publicAlice.toString());
		publicBob = generator.modPow(secretBob, prime);
		System.out.println("Public B: " + publicBob.toString());
		publicEve = generator.modPow(secretEve, prime);
		System.out.println("Public E: " + publicEve.toString());

		// Shared Key
		if (publicBob.modPow(secretAlice, prime).equals(publicAlice.modPow(secretBob, prime)))
			sharedKeyAliceBob = publicBob.modPow(secretAlice, prime);
		System.out.println("Shared AB: " + sharedKeyAliceBob.toString());
		if (publicEve.modPow(secretAlice, prime).equals(publicAlice.modPow(secretEve, prime)))
			sharedKeyAliceEve = publicEve.modPow(secretAlice, prime);
		System.out.println("Shared AE: " + sharedKeyAliceEve.toString());
		if (publicBob.modPow(secretEve, prime).equals(publicEve.modPow(secretBob, prime)))
			sharedKeyBobEve = publicBob.modPow(secretEve, prime);
		System.out.println("Shared BE: " + sharedKeyBobEve.toString());
		
		// Empty separator line.
		System.out.println();

		// Encryption - Decryption Setup
		try {
			// Initialize a SHA-256 message digest algorithm.
			messageDigest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		// Byte array for the key.
		byte[] key = null;
		byte[] keyAE = null;
		byte[] keyBE = null;
		try {
			// Digest the keys.
			key = messageDigest.digest(sharedKeyAliceBob.toString().getBytes("UTF-8"));
			keyAE = messageDigest.digest(sharedKeyAliceEve.toString().getBytes("UTF-8"));
			keyBE = messageDigest.digest(sharedKeyBobEve.toString().getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		key = Arrays.copyOf(key, 16);
		keyAE = Arrays.copyOf(keyAE, 16);
		keyBE = Arrays.copyOf(keyBE, 16);

		try {
			// Instantiate the AES cipher in encrypt mode with key.
			cipherEncrypAliceBob = Cipher.getInstance("AES");
			cipherEncrypAliceBob.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
			cipherEncryptAliceEve = Cipher.getInstance("AES");
			cipherEncryptAliceEve.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyAE, "AES"));
			cipherEncryptBobEve = Cipher.getInstance("AES");
			cipherEncryptBobEve.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBE, "AES"));
			// Instantiate the AES cipher in decrypt mode with key.
			cipherDecryptAliceBob = Cipher.getInstance("AES");
			cipherDecryptAliceBob.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
			cipherDecryptAliceEve = Cipher.getInstance("AES");
			cipherDecryptAliceEve.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyAE, "AES"));
			cipherDecryptBobEve = Cipher.getInstance("AES");
			cipherDecryptBobEve.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBE, "AES"));
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Prints the help message to the console.
	 * @since 1.1b
	 */
	private static void help(){
		
		// Empty separator line.
		System.out.println();
		
		// Introduction message.
		System.out.println("[System] This is a demonstration program for Diffie-Hellman Key Exchange Protocol.");
		System.out.println("[System] The program will generate keys which may take some time, please be patient.");
		System.out.println("[System] Once the keys are generated, the program will simulate a chatting application.");
		
		// List available commands.
		System.out.println("[System] Available commands:");
		System.out.println("\t -> help: Display this message.");
		System.out.println("\t -> renew: Renew the keys.");
		System.out.println("\t -> mitm: Toggle MITM mode.");
		System.out.println("\t -> exit: Exit the program.");
		
		// Empty separator line.
		System.out.println();
		
	}

	/**
	 * Generates a prime in given bit length and with certainty value of {@value #CERTAINTY}.
	 * @param bitLength Length of the prime to be generated in bits.
	 * @return Generated prime as a <code>BigInteger</code>.
	 * @see #CERTAINTY
	 * @since 1.0b
	 */
	private static BigInteger generatePrime(int bitLength) {
		// Generate a suitable prime for start.
		BigInteger prime = new BigInteger(bitLength, CERTAINTY, new SecureRandom());
		// Make sure the prime is a safe prime. (p-1/2 is also a prime)
		while (!prime.subtract(new BigInteger("1")).divide(new BigInteger("2")).isProbablePrime(CERTAINTY))
			// If not change the prime and try again.
			prime = new BigInteger(bitLength, CERTAINTY, new SecureRandom());
		return prime;
	}

	/**
	 * Generates a generator for the given prime.
	 * @param prime A prime <code>BigInteger</code> for a generator to be generated.
	 * @return <code>BigInteger</code> with a suitable generator value.
	 * @see #getPrimeRoot(BigInteger)
	 * @since 1.0b
	 */
	private static BigInteger generateGenerator(BigInteger prime) {
		// Generator is simply the prime root.
		return getPrimeRoot(prime);
	}

	/**
	 * Checks if the given value is a prime with predefined certainty.
	 * @param number Prime candidate to be tested as a <code>BigInteger</code>
	 * @return <code>true</code> if <code>n</code> is a prime with given certainty({@value #CERTAINTY}), <code>false</code> otherwise.
	 * @see #CERTAINTY
	 * @since 1.0b
	 */
	private static boolean isPrime(BigInteger number) {
		//Check if prime with certainty.
		return number.isProbablePrime(CERTAINTY);
	}

	/**
	 * Finds a prime root for the given prime value, searching between {@value #ROOT_START} to {@value #ROOT_END}.
	 * @param prime <code>BigInteger</code> value for which a prime root is to be found.
	 * @return Smallest prime root found for <code>p</code> as a <code>BigInteger</code>
	 * @see #ROOT_START
	 * @see #ROOT_END
	 * @since 1.0b
	 */
	private static BigInteger getPrimeRoot(BigInteger prime) {
		// Allow the root start to be changed by global variable.
		int i = ROOT_START;
		// Find the smallest generator starting from ROOT_START up to ROOT_END.
		for (; i < ROOT_END; i++)
			// Check if i is a suitable generator.
			if (isPrimeRoot(BigInteger.valueOf(i), prime))
				// Return i to be used as a generator.
				return BigInteger.valueOf(i);
		return new BigInteger("0");
	}

	/**
	 * Checks if the given generator candidate is a prime root for the given prime.
	 * @param generator <code>BigInteger</code> value for the generator candidate.
	 * @param prime <code>BigInteger</code> value for the prime.
	 * @return <code>true</code> if the candidate value is a generator for the prime, <code>false</code> otherwise.
	 * @since 1.0b
	 */
	private static boolean isPrimeRoot(BigInteger generator, BigInteger prime) {

		// Simply p-1.
		BigInteger pMinus = prime.subtract(new BigInteger("1"));
		// Prime factors of p-1.
		List<BigInteger> pFactors = primeFactors(pMinus);

		// Traverse the prime factors.
		for (int i = 0; i < pFactors.size(); i++)
			// Not a prime.
			if (generator.modPow(pMinus.divide(pFactors.get(i)), prime).equals(new BigInteger("1")))
				return false;
		return true;

	}

	/**
	 * Finds the prime factors of the given <code>BigInteger</code>.
	 * @param number <code>BigInteger</code> to factorize.
	 * @return <code>List&lt;BigInteger&gt;</code> with values corresponding to prime factors of <code>BigInteger n</code>.
	 * @see #FACTOR_LIMIT
	 * @since 1.0b
	 */
	private static List<BigInteger> primeFactors(BigInteger number) {

		// Divisor counter.
		BigInteger i = new BigInteger("2");

		// List of prime factors.
		List<BigInteger> pFactors = new ArrayList<BigInteger>();

		// While not completely factorized.
		while (!number.equals(new BigInteger("1"))) {
			while (number.mod(i).equals(new BigInteger("0"))) {
				// Add i as a factor.
				pFactors.add(i);
				// Divide n by i to defactorize by i.
				number = number.divide(i);
				if (isPrime(number)) {
					// If n is prime add and return the factors.
					pFactors.add(number);
					return pFactors;
				}
			}
			// Increase i to test bigger divisors.
			i = i.add(new BigInteger("1"));
			// Hard limit for time optimization. May need to address.
			if (i.equals(FACTOR_LIMIT))
				return pFactors;
		}
		return pFactors;

	}

	/**
	 * Certainty to use in prime generation and check.
	 * @see #generatePrime(int)
	 * @see #isPrime(BigInteger)
	 */
	private static final int CERTAINTY = 64;

	/**
	 * Length of keys to be used in bits.
	 * @see #init()
	 */
	private static final int KEY_LENGTH = 512;

	/**
	 * Hard coded limit to stop searching for factors.
	 * @see #primeFactors(BigInteger)
	 */
	private static final BigInteger FACTOR_LIMIT = new BigInteger("20000");

	/**
	 * Starting point for search.
	 * @see #getPrimeRoot(BigInteger)
	 */
	private static final int ROOT_START = 3;

	/**
	 * Ending point for search. (Note that if the program is reaching this point something is seriously wrong.)
	 * @see #getPrimeRoot(BigInteger)
	 */
	private static final int ROOT_END = 100000000;

}
