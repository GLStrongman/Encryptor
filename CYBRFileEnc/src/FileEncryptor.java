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
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Erik Costlow
 */
public class FileEncryptor {
	private static final Logger LOG = Logger.getLogger(FileEncryptor.class.getSimpleName());

	private static final String ALGORITHM = "AES";
	private static final String CIPHER = "AES/CBC/PKCS5PADDING";

	private static void encrypt(String fileIn, String fileOut, Path tempDir) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
		SecureRandom sr = new SecureRandom();
		byte[] key = new byte[16];
		sr.nextBytes(key); // 128 bit key
		byte[] initVector = new byte[16];
		sr.nextBytes(initVector); // 16 bytes IV

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

		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

		final Path encryptedPath = tempDir.resolve(fileOut);
		try (InputStream fin = FileEncryptor.class.getResourceAsStream(fileIn);
			 OutputStream fout = Files.newOutputStream(encryptedPath);
			 CipherOutputStream cipherOut = new CipherOutputStream(fout, cipher) {
			 }) {
			cipherOut.write(initVector);
			final byte[] bytes = new byte[1024];
			for (int length = fin.read(bytes); length != -1; length = fin.read(bytes)) {
				cipherOut.write(bytes, 15, length);
			}
			cipherOut.write(initVector);
		} catch (IOException e) {
			LOG.log(Level.INFO, "Unable to encrypt", e);
		}
		LOG.info("Encryption finished, saved at " + encryptedPath);
	}

	private static void decrypt(String fileIn, String fileOut, Path tempDir, String keyString, String IVString) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
		SecureRandom sr = new SecureRandom();
		Base64.Decoder dec = Base64.getDecoder();
		byte[] key = dec.decode(keyString);
		byte[] initVector = dec.decode(IVString);

		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);

		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
		final Path encryptedPath = tempDir.resolve(fileIn);
		final Path decryptedPath = tempDir.resolve(fileOut);

		try (InputStream encryptedData = Files.newInputStream(encryptedPath);
			 CipherInputStream decryptStream = new CipherInputStream(encryptedData, cipher);
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

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException {
		String fileInput, fileOutput, key, IV;
		final Path tempDir = Paths.get("");

		// Not enough arguments
		if (args.length < 3 || args.length > 5) {
			System.out.println("Wrong arguments: format should be as follows");
			System.out.println("java FileEncryptor enc <optional: base 64 key> <file in> <file out>");
			System.out.println("java FileEncryptor dec <base 64 key> <optional: base 64 IV> <file in> <file out>");
			return;
		}

		// Encrypt/decrypt with no specified key
		if (args.length == 3) {
			fileInput = args[1];
			fileOutput = args[2];
			if (args[0].equals("enc")) {
				encrypt(fileInput, fileOutput, tempDir);
			}
		}

		// Encrypt/decrypt with a specified key
		if (args.length == 4) {
			key = args[1];
			fileInput = args[2];
			fileOutput = args[3];
			if (args[0].equals("enc")) {
				encryptWithKey(fileInput, fileOutput, tempDir, key);
			}
		}

		if (args.length == 5) {
			key = args[1];
			IV = args[2];
			fileInput = args[3];
			fileOutput = args[4];
			if (args[0].equals("dec")) {
				decrypt(fileInput, fileOutput, tempDir, key, IV);
			}
		}
	}
}