import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Erik Costlow
 */
public class FileEncryptor {
	private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

	private static final String ALGORITHM = "AES";
	private static final String CIPHER = "AES/CBC/PKCS5PADDING";
	private static final String ENCRYPTION = "PBKDF2WithHmacSHA256";
	private static final String DEFAULT_LENGTH = "256";

	/**
	 * Basic encryption method which will generate a base64 key and IV
	 *
	 * @param fileIn plaintext
	 * @param fileOut ciphertext
	 * @param tempDir directory for files to sit in
	 */
	private static void encrypt(String fileIn, String fileOut, Path tempDir) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
		// Generate random key and IV, create metadata string
		SecureRandom sr = new SecureRandom();
		byte[] key = new byte[16];
		sr.nextBytes(key);
		byte[] initVector = new byte[16];
		sr.nextBytes(initVector);
		String metadata = "AES," + DEFAULT_LENGTH;
		byte[] mdByte = metadata.getBytes();
		// Print key and IV
		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + enc.encodeToString(key));
		System.out.println("initVector=" + enc.encodeToString(initVector));
		// Initialize cipher and secret key
		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
		final Path encryptedPath = tempDir.resolve(fileOut);
		// Read in plaintext and write out IV, metadata, and encoded text to ciphertext file
		try (InputStream fin = FileEncryptor.class.getResourceAsStream(fileIn);
			 OutputStream fout = Files.newOutputStream(encryptedPath);
			 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
			 }) {
			fout.write(initVector);
			fout.write(mdByte);
			final byte[] bytes = new byte[1024];
			for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
				cipherOut.write(bytes, 0, length);
			}
		// Catch errors and print readable error messages to customer
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		} catch (NullPointerException e) {
			LOG.log(Level.INFO, "Invalid file, please provide a valid file");
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	/**
	 * Encryption method which will generate an IV and use the user's specified key
	 *
	 * @param fileIn plaintext
	 * @param fileOut ciphertext
	 * @param tempDir directory for files to sit in
	 * @param keyString user specified base 64 key
	 */
	private static void encryptWithKey(String fileIn, String fileOut, Path tempDir, String keyString)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException {
		// Generate random IV, decode key to bytes, create metadata string
		SecureRandom sr = new SecureRandom();
		Base64.Decoder dec = Base64.getDecoder();
		byte[] key = dec.decode(keyString);
		byte[] initVector = new byte[16];
		sr.nextBytes(initVector);
		String metadata = "AES," + DEFAULT_LENGTH;
		byte[] mdByte = metadata.getBytes();
		// Print key and IV
		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + enc.encodeToString(key));
		System.out.println("initVector=" + enc.encodeToString(initVector));
		// Initialize cipher and secret key
		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
		final Path encryptedPath = tempDir.resolve(fileOut);
		// Read in plaintext and write out IV, metadata, and encoded text to ciphertext file
		try (InputStream fin = FileEncryptor.class.getResourceAsStream(fileIn);
			 OutputStream fout = Files.newOutputStream(encryptedPath);
			 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
			 }) {
			fout.write(initVector);
			fout.write(mdByte);
			final byte[] bytes = new byte[1024];
			for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
				cipherOut.write(bytes, 0, length);
			}
		// Catch errors and print readable error messages to customer
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		} catch (NullPointerException e) {
			LOG.log(Level.INFO, "Invalid file, please provide a valid file");
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	/**
	 * Encryption method which will generate a base 64 key and IV from the user's specified password
	 *
	 * @param fileIn plaintext
	 * @param fileOut ciphertext
	 * @param tempDir directory for files to sit in
	 * @param userPassword user specified base 64 key
	 */
	private static void encryptWithPassword(String fileIn, String fileOut, Path tempDir, String userPassword)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, InvalidKeySpecException {
		// Generate random IV, create metadata string
		SecureRandom sr = new SecureRandom();
		byte[] initVector = new byte[16];
		sr.nextBytes(initVector);
		String metadata = "AES," + DEFAULT_LENGTH;
		int keyLength = Integer.parseInt(DEFAULT_LENGTH);
		byte[] mdByte = metadata.getBytes();
		// Convert password to character array, generate secret key from password and IV
		char[] password = userPassword.toCharArray();
		KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, keyLength);
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance(ENCRYPTION);
		SecretKey pbeKey = keyFac.generateSecret(keySpec);
		SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);
		// Print key and IV
		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + enc.encodeToString(sKey.getEncoded()));
		System.out.println("initVector=" + enc.encodeToString(initVector));
		// Initialize cipher and secret key
		IvParameterSpec iv = new IvParameterSpec(initVector);
		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, sKey, iv);
		final Path encryptedPath = tempDir.resolve(fileOut);
		// Read in plaintext and write out IV, metadata, and encoded text to ciphertext file
		try (InputStream fin = FileEncryptor.class.getResourceAsStream(fileIn);
			 OutputStream fout = Files.newOutputStream(encryptedPath);
			 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
			 }) {
			fout.write(initVector);
			fout.write(mdByte);
			final byte[] bytes = new byte[1024];
			for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
				cipherOut.write(bytes, 0, length);
			}
		// Catch errors and print readable error messages to customer
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		} catch (NullPointerException e) {
			LOG.log(Level.INFO, "Invalid file, please provide a valid file");
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	/**
	 * Encryption method which will generate a base 64 key and IV from the user's specified password.
	 * Will use AES encryption, and user's specified keylength.
	 *
	 * @param fileIn plaintext
	 * @param fileOut ciphertext
	 * @param tempDir directory for files to sit in
	 * @param userPassword user specified base 64 key
	 * @param userKeyLength user specified key length
	 */
	private static void encryptWithPasswordAES(String fileIn, String fileOut, Path tempDir, String userPassword, String userKeyLength)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, InvalidKeySpecException {
		// Generate random IV, create metadata string
		SecureRandom sr = new SecureRandom();
		byte[] initVector = new byte[16];
		sr.nextBytes(initVector);
		int keyLength = Integer.parseInt(userKeyLength);
		String metadata = "AES," + keyLength;
		byte[] mdByte = metadata.getBytes();
		// Convert password to character array, generate secret key from password and IV
		char[] password = userPassword.toCharArray();
		KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, keyLength);
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance(ENCRYPTION);
		SecretKey pbeKey = keyFac.generateSecret(keySpec);
		SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);
		// Print key and IV
		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + enc.encodeToString(sKey.getEncoded()));
		System.out.println("initVector=" + enc.encodeToString(initVector));
		// Initialize cipher and secret key
		IvParameterSpec iv = new IvParameterSpec(initVector);
		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, sKey, iv);
		final Path encryptedPath = tempDir.resolve(fileOut);
		// Read in plaintext and write out IV, metadata, and encoded text to ciphertext file
		try (InputStream fin = FileEncryptor.class.getResourceAsStream(fileIn);
			 OutputStream fout = Files.newOutputStream(encryptedPath);
			 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
			 }) {
			fout.write(initVector);
			fout.write(mdByte);
			final byte[] bytes = new byte[1024];
			for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
				cipherOut.write(bytes, 0, length);
			}
		// Catch errors and print readable error messages to customer
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	/**
	 * Encryption method which will generate a base 64 key and IV from the user's specified password.
	 * Will use Blowfish encryption, and user's specified key length.
	 *
	 * @param fileIn plaintext
	 * @param fileOut ciphertext
	 * @param tempDir directory for files to sit in
	 * @param userPassword user specified base 64 key
	 * @param userKeyLength user specified key length
	 */
	private static void encryptWithPasswordBF(String fileIn, String fileOut, Path tempDir, String userPassword, String userKeyLength)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, InvalidKeySpecException {
		// Generate random IV, create metadata string
		SecureRandom sr = new SecureRandom();
		int keyLength = Integer.parseInt(userKeyLength);
		String metadata = "BFA," + keyLength;
		byte[] mdByte = metadata.getBytes();
		byte[] initVector = new byte[16];
		sr.nextBytes(initVector);
		// Convert password to character array, generate secret key from password and IV
		char[] password = userPassword.toCharArray();
		KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, keyLength);
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance(ENCRYPTION);
		SecretKey pbeKey = keyFac.generateSecret(keySpec);
		SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), "Blowfish");
		// Print key and IV
		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + enc.encodeToString(sKey.getEncoded()));
		System.out.println("initVector=" + enc.encodeToString(initVector));
		// Initialize cipher
		Cipher cipher = Cipher.getInstance("Blowfish");
		cipher.init(Cipher.ENCRYPT_MODE, sKey);
		final Path encryptedPath = tempDir.resolve(fileOut);
		// Read in plaintext and write out IV, metadata, and encoded text to ciphertext file
		try (InputStream fin = FileEncryptor.class.getResourceAsStream(fileIn);
			 OutputStream fout = Files.newOutputStream(encryptedPath);
			 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
			 }) {
			fout.write(initVector);
			fout.write(mdByte);
			final byte[] bytes = new byte[1024];
			for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
				cipherOut.write(bytes, 0, length);
			}
		// Catch errors and print readable error messages to customer
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	/**
	 * Decryption method using specified base 64 key and IV
	 *
	 * @param fileIn plaintext
	 * @param fileOut ciphertext
	 * @param tempDir directory for files to sit in
	 * @param keyString specified base 64 key
	 * @param IVString specified IV
	 */
	private static void decrypt(String fileIn, String fileOut, Path tempDir, String keyString, String IVString) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
		// Decode key and IV from strings to bytes
		Base64.Decoder dec = Base64.getDecoder();
		byte[] key = dec.decode(keyString);
		byte[] initVector = dec.decode(IVString);
		byte[] fileIV = new byte[16];
		byte[] mdByte = new byte[7];
		// Define file in/out pathways
		final Path encryptedPath = tempDir.resolve(fileIn);
		final Path decryptedPath = tempDir.resolve(fileOut);
		// Generate secret key and initialize cipher, read in metadata from file
		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER);
		InputStream encryptedData = Files.newInputStream(encryptedPath);
		encryptedData.read(fileIV);
		encryptedData.read(mdByte);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
		// Read in ciphertext and write out decrypted text to plaintext file
		try ( CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
				 OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
			final byte[] bytes = new byte[1024];
			for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
				decryptedOut.write(bytes, 0, length);
			}
		// Catch errors and print readable error messages to customer
		} catch (IOException ex) {
			Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
		}
		LOG.info("Decryption complete, open " + decryptedPath);
	}

	/**
	 * Decryption method using specified base 64 key and metadata IV
	 *
	 * @param fileIn plaintext
	 * @param fileOut ciphertext
	 * @param tempDir directory for files to sit in
	 * @param keyString specified base 64 key
	 */
	private static void decryptWithoutIV(String fileIn, String fileOut, Path tempDir, String keyString) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException {
		// Decode key from string to bytes, generate IV
		Base64.Decoder dec = Base64.getDecoder();
		byte[] key = dec.decode(keyString);
		final byte[] initVector = new byte[16];
		byte[] mdByte = new byte[7];
		// Define file paths and create cipher
		final Path encryptedPath = tempDir.resolve(fileIn);
		final Path decryptedPath = tempDir.resolve(fileOut);
		Cipher cipher = Cipher.getInstance(CIPHER);
		// Read in and initialize IV
		InputStream encryptedData = Files.newInputStream(encryptedPath);
		encryptedData.read(initVector);
		encryptedData.read(mdByte);
		IvParameterSpec iv = new IvParameterSpec(initVector);
		// Create secret key, intialize cipher
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
		// Read in ciphertext and write out decrypted text to plaintext file
		try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
				 OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
			final byte[] bytes = new byte[1024];
			for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
				decryptedOut.write(bytes, 0, length);
			}
		// Catch errors and print readable error messages to customer
		} catch (IOException ex) {
			Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
		}
		LOG.info("Decryption complete, open " + decryptedPath);
	}

	/**
	 * Decryption method using specified password to generate key
	 *
	 * @param fileIn plaintext
	 * @param fileOut ciphertext
	 * @param tempDir directory for files to sit in
	 * @param userPassword specified password
	 */
	private static void decryptWithPassword(String fileIn, String fileOut, Path tempDir, String userPassword) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, InvalidKeySpecException, BadPaddingException {
		byte[] initVector = new byte[16];
		byte[] mdByte = new byte[7];
		// Define file paths and read in metadata
		final Path encryptedPath = tempDir.resolve(fileIn);
		final Path decryptedPath = tempDir.resolve(fileOut);
		InputStream encryptedData = Files.newInputStream(encryptedPath);
		encryptedData.read(initVector);
		encryptedData.read(mdByte);
		// Parse metadata
		String metadata = new String(mdByte);
		String[] mdInfo = metadata.split(",");
		int keyLength = Integer.parseInt(mdInfo[1]);
		// Convert password to character array
		char[] password = userPassword.toCharArray();
		Cipher cipher;
		// Decrypt using AES
		if (mdInfo[0].equals("AES")){
			// Generate secret key
			KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, keyLength);
			SecretKeyFactory keyFac = SecretKeyFactory.getInstance(ENCRYPTION);
			SecretKey pbeKey = keyFac.generateSecret(keySpec);
			SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);
			IvParameterSpec iv = new IvParameterSpec(initVector);
			// Initialize cipher
			cipher = Cipher.getInstance(CIPHER);
			cipher.init(Cipher.DECRYPT_MODE, sKey, iv);
		}
		// Decrypt using Blowfish
		else {
			// Generate secret key
			KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, keyLength);
			SecretKeyFactory keyFac = SecretKeyFactory.getInstance(ENCRYPTION);
			SecretKey pbeKey = keyFac.generateSecret(keySpec);
			SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), "Blowfish");
			IvParameterSpec iv = new IvParameterSpec(initVector);
			// Initialize cipher
			cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, sKey);
		}
		// Read in cipher text and write out decrypted text to plaintext file
		try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
			 OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
			final byte[] bytes = new byte[1024];
			for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
				decryptedOut.write(bytes, 0, length);
			}
		// Catch errors and print readable error messages to customer
		} catch (IOException ex) {
			throw new BadPaddingException();
		}
		LOG.info("Decryption complete, open " + decryptedPath);
	}

	/**
	 * Guide printed with instructions of how to use program and possible arguments
	 */
	private static void wrongArg(){
		System.out.println("Wrong arguments, format should be as follows:\n");
		System.out.println("With password:");
		System.out.println("java FileEncryptor enc (<AES / Blowfish>) (<key length>) <password> <file in> <file out>");
		System.out.println("java FileEncryptor dec <password> <file in> <file out>\n");

		System.out.println("Without password:");
		System.out.println("java FileEncryptor enc (<base 64 key>) <file in> <file out>");
		System.out.println("java FileEncryptor dec (<base 64 key>) (<base 64 IV>) <file in> <file out>");
	}

	/**
	 * Get metadata from ciphertext and print information
	 *
	 * @param fileIn ciphertext
	 * @param tempDir directory for files to sit in
	 */
	private static void info(String fileIn, Path tempDir) throws IOException {
		byte[] initVector = new byte[16];
		byte[] mdByte = new byte[7];
		// Define file path and read in metadata
		final Path encryptedPath = tempDir.resolve(fileIn);
		InputStream encryptedData = Files.newInputStream(encryptedPath);
		encryptedData.read(initVector);
		encryptedData.read(mdByte);
		// Parse metadata
		String metadata = new String(mdByte);
		String[] mdInfo = metadata.split(",");
		// Print algorithm and key length
		if (mdInfo[0].equals("BFA")){
			System.out.println("Blowfish " + mdInfo[1]);
		}
		else if (mdInfo[0].equals("AES")){
			System.out.println("AES " + mdInfo[1]);
		}
		else {
			System.out.println("File doesn't seem to contain any metadata");
		}
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, BadPaddingException {
		String fileInput, fileOutput, key, IV, algorithm, keyLength;
		final Path tempDir = Paths.get("");
		try {
			switch(args.length){
				// Show metadata of file
				case 2:
					if (args[0].equals("info")){
						fileInput = args[1];
						info(fileInput, tempDir);
					}
					else {
						wrongArg();
					}
					break;
				// Encryption with basic arguments
				case 3:
					fileInput = args[1];
					fileOutput = args[2];
					if (args[0].equals("enc")) {
						encrypt(fileInput, fileOutput, tempDir);
					}
					else {
						wrongArg();
					}
					break;
				// Encryption with a key or password, or decryption without an IV/with a password
				case 4:
					key = args[1];
					fileInput = args[2];
					fileOutput = args[3];
					// Check if user has given a key
					if (key.contains("A==") || key.contains("g==") || key.contains("w==") || key.contains("Q==")) {
						if (args[0].equals("enc")) {
							encryptWithKey(fileInput, fileOutput, tempDir, key);
						} else if (args[0].equals("dec")) {
							decryptWithoutIV(fileInput, fileOutput, tempDir, key);
						} else {
							wrongArg();
						}
					}
					// Assume user has given a password
					else {
						if (args[0].equals("enc")) {
							encryptWithPassword(fileInput, fileOutput, tempDir, key);
						}
						else if (args[0].equals("dec")){
							decryptWithPassword(fileInput, fileOutput, tempDir, key);
						}
						else {
							wrongArg();
						}
					}
					break;
				// Encryption with specified algorithm but no specified key length, or decryption with IV and key
				case 5:
					fileInput = args[3];
					fileOutput = args[4];
					if (args[0].equals("enc")) {
						algorithm = args[1].toLowerCase();
						key = args[2];
						if (algorithm.equals("aes")) {
							encryptWithPasswordAES(fileInput, fileOutput, tempDir, key, DEFAULT_LENGTH);
						}
						else if (algorithm.equals("bf") || algorithm.equals("blowfish")){
							encryptWithPasswordBF(fileInput, fileOutput, tempDir, key, DEFAULT_LENGTH);
						}
						else {
							System.out.println("Invalid encryption method, try AES or Blowfish");
						}
					}
					else if (args[0].equals("dec")) {
						key = args[1];
						IV = args[2];
						decrypt(fileInput, fileOutput, tempDir, key, IV);
					}
					else {
						wrongArg();
					}
					break;
				// Encryption with specified algorithm and specified key length
				case 6:
					algorithm = args[1].toLowerCase();
					keyLength = args[2];
					key = args[3];
					fileInput = args[4];
					fileOutput = args[5];
					if (Integer.parseInt(keyLength) > 999){
						System.out.println("Key length is too big, please use a key of length 999 or less");
					}
					else if (args[0].equals("enc")){
						if (algorithm.equals("aes")){
							encryptWithPasswordAES(fileInput, fileOutput, tempDir, key, keyLength);
						}
						else if (algorithm.equals("bf") || algorithm.equals("blowfish")){
							encryptWithPasswordBF(fileInput, fileOutput, tempDir, key, keyLength);
						}
						else {
							System.out.println("Invalid encryption method, try AES or Blowfish");
						}
					}
					else {
						wrongArg();
					}
					break;
				default:
					wrongArg();
					break;
			}

		} catch (InvalidKeyException e) {
			LOG.info("Key is not valid, please provide a valid Base64 key");
		} catch (IOException e) {
			LOG.info("Input/output file is not valid, please provide a valid file");
		} catch (InvalidKeySpecException e) {
			LOG.info("Password is not valid, please provide a valid password");
		} catch (BadPaddingException e) {
			LOG.info("Unable to decrypt - are you sure your key is correct?");
		}
	}
}