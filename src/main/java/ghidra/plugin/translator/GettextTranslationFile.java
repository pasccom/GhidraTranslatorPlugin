package ghidra.plugin.translator;

import java.io.File;
import java.io.IOException;
import java.nio.file.AccessMode;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.FileByteProvider;

/**
 * GetText based translation file.
 *
 * This class implements the TranslationFile interface
 * for the GetText format (*.mo files).
 *
 * @author pascom@orange.fr
 */
public class GettextTranslationFile implements TranslationFile
{
	/**
	 * Utility class to store string information.
	 * @author Pascal COMBES
	 */
	private class StringInfo
	{
		/** The length of the string */
		public int length;
		/** The offset of the string */
		public long offset;
	}

	/** The reader for the physical file */
	private BinaryReader reader;
	/** Major version of the translation file */
	private int majorVersion;
	/** Minor version of the translation file */
	private int minorVersion;
	/** The size of the translation file */
	private long size;
	/** Offset of messages in file */
	private long msgIdsOffset;
	/** Offset of translations in file */
	private long translationsOffset;

	/**
	 * This function initializes a new GetText translation file abstraction.
	 * It uses the given version information and also reads the translation
	 * file header.
	 * @param reader The reader for the physical file
	 * @param major Major version of the translation file
	 * @param minor Minor version of the translation file
	 * @see create(String)
	 * @see create(File)
	 */
	private GettextTranslationFile(BinaryReader reader, int major, int minor)
	{
		this.reader = reader;
		this.majorVersion = major;
		this.minorVersion = minor;
		readHeader();
	}

	/**
	 * This function creates a new GetText translation file
	 * from the file at the given path.
	 *
	 * It checks that the magic corresponds to the magic of
	 * GetText translation files and that the version of the
	 * translation file is supported.
	 * @param filePath Path to the translation file.
	 * @return A new GetText translation file abstraction or null
	 * if the file at the given path is not supported.
	 * @see create(File)
	 */
	public static GettextTranslationFile create(String filePath)
	{
		return create(new File(filePath));
	}

	/**
	 * This function creates a new GetText translation file
	 * from the given file.
	 *
	 * It checks that the magic corresponds to the magic of
	 * GetText translation files and that the version of the
	 * translation file is supported.
	 * @param file The translation file.
	 * @return A new GetText translation file abstraction or null
	 * if the given file is not supported.
	 * @see create(String)
	 */
	public static GettextTranslationFile create(File file)
	{
		BinaryReader reader;
		try {
			reader = new BinaryReader(new FileByteProvider(file, null, AccessMode.READ), true);
		} catch (IOException e1) {
			System.out.println("ERROR File not found: " + file.getAbsolutePath());
			return null;
		}

		boolean ok = false;
		// Read and check magic
		try {
			long magic = reader.readNextUnsignedInt();
			if (magic == 0x950412del)
				ok = true;
			else
				System.out.println(String.format("ERROR Invalid magic: 0x%08X", magic));
		} catch (IOException e) {
			System.out.println("ERROR Could not read magic");
		}
		if (ok == true) {
			// Read and check version
			ok = false;
			try {
				int minorVersion = reader.readNextUnsignedShort();
				int majorVersion = reader.readNextUnsignedShort();
				if (majorVersion == 0)
					return new GettextTranslationFile(reader, majorVersion, minorVersion);
				else
					System.out.println(String.format("ERROR Only version 0.x is supported. Got: %d.%d", majorVersion, minorVersion));
			} catch (IOException e) {
				System.out.println("ERROR Could not read version");
			}
		}

		try {
			reader.getByteProvider().close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * This function reads the header of the GetText translation file.
	 *
	 * The header contains the size of the translation file
	 * (i.e. the number of strings in the translation file)
	 * and the offsets to the messages and the translations.
	 */
	private void readHeader()
	{
		try {
			size = reader.readNextUnsignedInt();
			System.out.println(String.format("DEBUG Number of strings: %d", size));
		} catch (IOException e) {
			System.out.println("ERROR Could not read number of strings");
			size = 0;
		}
		try {
			msgIdsOffset = reader.readNextUnsignedInt();
			System.out.println(String.format("DEBUG Offset of messages: 0x%08X", msgIdsOffset));
		} catch (IOException e) {
			System.out.println("ERROR Could not read offset of messages");
			msgIdsOffset = 0;
		}
		try {
			translationsOffset = reader.readNextUnsignedInt();
			System.out.println(String.format("DEBUG Offset of translations: 0x%08X", translationsOffset));
		} catch (IOException e) {
			System.out.println("ERROR Could not read offset of translations");
			translationsOffset = 0;
		}
	}

	/**
	 * @inheritDoc
	 */
	@Override
	public String getInformation() {
		return String.format("Translation file version: %d.%d\n", majorVersion, minorVersion)
		     + getString(getInfo(translationsOffset));
	}

	/**
	 * @inheritDoc
	 */
	@Override
	public String getTranslation(String msgId) {
		long index = findMessage(msgId);
		if (index == -1)
			return null;
		return getString(getInfo(translationsOffset + 8 * index));
	}

	/**
	 * This function searches the given message in the translation file.
	 *
	 * Since the messages are sorted in alphabetical order,
	 * it uses a dichotomy.
	 * @param msgId The message to search for
	 * @return The offset of the given message
	 * or -1 if the message is not found.
	 */
	private long findMessage(String msgId)
	{
		long l = 0;
		long r = size - 1;

		while (l < r) {
			long m = (l + r) / 2;
			String s = getString(getInfo(msgIdsOffset + 8 * m));
			if (s == null)
				return -1;

			if (m != l) {
				if (msgId.compareTo(s) < 0) // msgId < s
					r = m;
				else if (msgId.compareTo(s) > 0) // msgId > s
					l = m;
				else
					return m;
			} else {
				if (msgId.equals(s))
					return m;
				else
					l = r;
			}
		}

		long m = (l + r) / 2;
		String s = getString(getInfo(msgIdsOffset + 8 * m));
		if (s == null)
			return -1;

		if (!msgId.equals(s))
			return -1;
		return m;
	}

	/**
	 * This function returns the StringInfo at the given offset.
	 * @param offset The offset where the StringInfo is stored.
	 * @return The StringInfo at the given offset.
	 */
	private StringInfo getInfo(long offset)
	{
		StringInfo info = new StringInfo();

		reader.setPointerIndex(offset);
		try {
			info.length = (int) reader.readNextUnsignedInt();
			info.offset = reader.readNextUnsignedInt();
		} catch (IOException e) {
			System.out.println(String.format("ERROR Could not get information at offset 0x%08X", offset));
			return null;
		}

		return info;
	}

	/**
	 * This function returns the string for the given StringInfo.
	 * @param info The information on the string to retrieve.
	 * @return The string corresponding to the given StringInfo.
	 */
	private String getString(StringInfo info)
	{
		if (info == null)
			return null;

		try {
			return new String(reader.readByteArray(info.offset, info.length), "UTF-8");
		} catch (IOException e) {
			System.out.println(String.format("ERROR Could not get string at offset 0x%08X", info.offset));
			return null;
		}
	}
}
