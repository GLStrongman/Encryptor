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
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Erik Costlow
 */
public class FileEncryptor {
	private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

	private static final String ALGORITHM = "AES";
	private static final String CIPHER = "AES/CBC/PKCS5PADDING";

	private static void encrypt(String fileIn, String fileOut, Path tempDir) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
		SecureRandom sr = new SecureRandom();
		byte[] key = new byte[16];
		sr.nextBytes(key); // 128 bit key
		byte[] initVector = new byte[16];
		sr.nextBytes(initVector); // 16 bytes IV
		String metadata = "AES," + "256";
		byte[] mdByte = new byte[7];
		mdByte = metadata.getBytes();

		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + enc.encodeToString(key));
		System.out.println("initVector=" + enc.encodeToString(initVector));

		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

		final Path encryptedPath = tempDir.resolve(fileOut);
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
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	private static void encryptWithKey(String fileIn, String fileOut, Path tempDir, String keyString)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException {
		SecureRandom sr = new SecureRandom();
		Base64.Decoder dec = Base64.getDecoder();
		byte[] key = dec.decode(keyString);
		byte[] initVector = new byte[16];
		sr.nextBytes(initVector); // 16 bytes IV
		String metadata = "AES," + "256";
		byte[] mdByte = new byte[7];
		mdByte = metadata.getBytes();

		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + enc.encodeToString(key));
		System.out.println("initVector=" + enc.encodeToString(initVector));

		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

		final Path encryptedPath = tempDir.resolve(fileOut);

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
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	private static void encryptWithPassword(String fileIn, String fileOut, Path tempDir, String userPassword)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, InvalidKeySpecException {
		SecureRandom sr = new SecureRandom();

		byte[] initVector = new byte[16];
		sr.nextBytes(initVector);
		String metadata = "AES," + "256";
		byte[] mdByte = new byte[7];
		mdByte = metadata.getBytes();

		char[] password = userPassword.toCharArray();

		KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, 256);
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		SecretKey pbeKey = keyFac.generateSecret(keySpec);
		SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);

		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + sKey);
		System.out.println("initVector=" + enc.encodeToString(initVector));

		IvParameterSpec iv = new IvParameterSpec(initVector);

		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, sKey, iv);

		final Path encryptedPath = tempDir.resolve(fileOut);

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
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	private static void encryptWithPasswordAES(String fileIn, String fileOut, Path tempDir, String userPassword, String userKeyLength)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, InvalidKeySpecException {
		SecureRandom sr = new SecureRandom();

		byte[] initVector = new byte[16];
		sr.nextBytes(initVector);
		int keyLength = Integer.parseInt(userKeyLength);
		String metadata = "AES," + keyLength;
		byte[] mdByte = new byte[7];
		mdByte = metadata.getBytes();

		char[] password = userPassword.toCharArray();

		KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, keyLength);
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		SecretKey pbeKey = keyFac.generateSecret(keySpec);
		SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);

		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + enc.encodeToString(sKey.getEncoded()));
		System.out.println("initVector=" + enc.encodeToString(initVector));

		IvParameterSpec iv = new IvParameterSpec(initVector);

		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, sKey, iv);

		final Path encryptedPath = tempDir.resolve(fileOut);

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
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	private static void encryptWithPasswordBF(String fileIn, String fileOut, Path tempDir, String userPassword, String userKeyLength)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, InvalidKeySpecException {
		SecureRandom sr = new SecureRandom();

		int keyLength = Integer.parseInt(userKeyLength);
		String metadata = "BFA," + keyLength;
		byte[] mdByte = new byte[7];
		mdByte = metadata.getBytes();
		byte[] initVector = new byte[16];
		sr.nextBytes(initVector);

		char[] password = userPassword.toCharArray();
		System.out.println("Hi there" + userPassword);

		KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, keyLength);
		SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		SecretKey pbeKey = keyFac.generateSecret(keySpec);
		SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), "Blowfish");

		Base64.Encoder enc =  Base64.getEncoder();
		System.out.println("Random key=" + enc.encodeToString(sKey.getEncoded()));
		System.out.println("initVector=" + enc.encodeToString(initVector));

		IvParameterSpec iv = new IvParameterSpec(initVector);

		Cipher cipher = Cipher.getInstance("Blowfish");
		cipher.init(Cipher.ENCRYPT_MODE, sKey);

		final Path encryptedPath = tempDir.resolve(fileOut);

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
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}


	private static void decrypt(String fileIn, String fileOut, Path tempDir, String keyString, String IVString) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
		Base64.Decoder dec = Base64.getDecoder();
		byte[] key = dec.decode(keyString);
		byte[] initVector = dec.decode(IVString);
		byte[] fileIV = new byte[16];
		byte[] mdByte = new byte[7];
		final Path encryptedPath = tempDir.resolve(fileIn);
		final Path decryptedPath = tempDir.resolve(fileOut);

		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER);
		InputStream encryptedData = Files.newInputStream(encryptedPath);
		encryptedData.read(fileIV);
		encryptedData.read(mdByte);

		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

		try ( CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
				 OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
			final byte[] bytes = new byte[1024];
			for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
				decryptedOut.write(bytes, 0, length);
			}
		} catch (IOException ex) {
			Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
		}

		LOG.info("Decryption complete, open " + decryptedPath);
	}

	private static void decryptWithoutIV(String fileIn, String fileOut, Path tempDir, String keyString) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException {
		Base64.Decoder dec = Base64.getDecoder();
		byte[] key = dec.decode(keyString);
		final byte[] initVector = new byte[16];
		byte[] mdByte = new byte[7];
		final Path encryptedPath = tempDir.resolve(fileIn);
		final Path decryptedPath = tempDir.resolve(fileOut);
		Cipher cipher = Cipher.getInstance(CIPHER);

		InputStream encryptedData = Files.newInputStream(encryptedPath);

		encryptedData.read(initVector);
		encryptedData.read(mdByte);

		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

		try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
				 OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
			final byte[] bytes = new byte[1024];
			for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
				decryptedOut.write(bytes, 0, length);
			}
		} catch (IOException ex) {
			Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
		}

		LOG.info("Decryption complete, open " + decryptedPath);
	}

	private static void decryptWithPassword(String fileIn, String fileOut, Path tempDir, String userPassword) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, InvalidKeySpecException, BadPaddingException {
		byte[] initVector = new byte[16];
		byte[] mdByte = new byte[7];
		final Path encryptedPath = tempDir.resolve(fileIn);
		final Path decryptedPath = tempDir.resolve(fileOut);

		InputStream encryptedData = Files.newInputStream(encryptedPath);
		encryptedData.read(initVector);
		encryptedData.read(mdByte);

		String metadata = new String(mdByte);
		String[] mdInfo = metadata.split(",");
		int keyLength = Integer.parseInt(mdInfo[1]);
		char[] password = userPassword.toCharArray();
		Cipher cipher = Cipher.getInstance(CIPHER);

		if (mdInfo[0].equals("AES")){
			KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, keyLength);
			SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			SecretKey pbeKey = keyFac.generateSecret(keySpec);
			SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), ALGORITHM);

			IvParameterSpec iv = new IvParameterSpec(initVector);

			cipher = Cipher.getInstance(CIPHER);
			cipher.init(Cipher.DECRYPT_MODE, sKey, iv);
		}
		else {
			KeySpec keySpec = new PBEKeySpec(password, initVector, 65536, keyLength);
			SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			SecretKey pbeKey = keyFac.generateSecret(keySpec);
			SecretKey sKey = new SecretKeySpec(pbeKey.getEncoded(), "Blowfish");

			IvParameterSpec iv = new IvParameterSpec(initVector);

			cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, sKey);
		}

		try (CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
			 OutputStream decryptedOut = Files.newOutputStream(decryptedPath)) {
			final byte[] bytes = new byte[1024];
			for (int length = decryptStream.read(bytes); length != -1; length = decryptStream.read(bytes)) {
				decryptedOut.write(bytes, 0, length);
			}
		} catch (IOException ex) {
			//Logger.getLogger(FileEncryptor.class.getName()).log(Level.SEVERE, "Unable to decrypt", ex);
			throw new BadPaddingException();
		}

		LOG.info("Decryption complete, open " + decryptedPath);
	}



	private static void wrongArg(){
		System.out.println("Wrong arguments: format should be as follows");
		System.out.println("java FileEncryptor enc <optional: base 64 key> <file in> <file out>");
		System.out.println("java FileEncryptor dec <base 64 key> <optional: base 64 IV> <file in> <file out>");
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, BadPaddingException {
		String fileInput, fileOutput, key, IV, algorithm, keyLength;
		final Path tempDir = Paths.get("");

		try {
			// Show metadata
			if (args.length == 2){

			}

			// Encrypt with no specified key
			if (args.length == 3) {
				fileInput = args[1];
				fileOutput = args[2];
				if (args[0].equals("enc")) {
					encrypt(fileInput, fileOutput, tempDir);
				}
				else {
					wrongArg();
				}
			}

			// Encrypt/decrypt with a specified key
			else if (args.length == 4) {
				key = args[1];
				fileInput = args[2];
				fileOutput = args[3];
				// Check if user has given a key
				if (key.contains("A==") || key.contains("g==") || key.contains("w==") || key.contains("Q==")){
					if (args[0].equals("enc")) {
						encryptWithKey(fileInput, fileOutput, tempDir, key);
					}
					else if (args[0].equals("dec")){
						decryptWithoutIV(fileInput, fileOutput, tempDir, key);
					}
					else {
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
			}

			else if (args.length == 5) {
				key = args[1];
				IV = args[2];
				fileInput = args[3];
				fileOutput = args[4];
				if (args[0].equals("dec")) {
					decrypt(fileInput, fileOutput, tempDir, key, IV);
				}
				else {
					wrongArg();
				}
			}

			else if (args.length == 6){
				algorithm = args[1].toLowerCase();
				keyLength = args[2];
				key = args[3];
				fileInput = args[4];
				fileOutput = args[5];
				if (Integer.parseInt(keyLength) > 999){
					System.out.println("Key length is too big, please use a key of length 999 or less.");
				}
				else if (args[0].equals("enc")){
					if (algorithm.equals("aes")){
						encryptWithPasswordAES(fileInput, fileOutput, tempDir, key, keyLength);
					}
					else if (algorithm.equals("bf") || algorithm.equals("blowfish")){
						encryptWithPasswordBF(fileInput, fileOutput, tempDir, key, keyLength);
					}
					else {
						System.out.println("Invalid encryption method, try AES or Blowfish.");
					}
				}
				else {
					wrongArg();
				}
			}

			// Not enough/too many arguments
			else {
				wrongArg();
			}

		} catch (InvalidKeyException e) {
			LOG.info("Key is not valid, please provide a valid Base64 key.");
		} catch (IOException e) {
			LOG.info("Input/output file is not valid, please provide a valid file.");
		} catch (InvalidKeySpecException e) {
			LOG.info("Password is not valid, please provide a valid password.");
		} catch (BadPaddingException e) {
			LOG.info("Unable to decrypt - are you sure your key is correct?");
		}
	}
}