package ghidra.plugin.translator;

import java.io.File;
import java.io.IOException;
import java.nio.file.AccessMode;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.FileByteProvider;

public class GettextTranslationFile implements TranslationFile
{
	private class StringInfo
	{
		public int length;
		public long offset;
	}
	
	
	private BinaryReader reader;
	private long size;
	private long msgIdsOffset;
	private long translationsOffset;
	
	private GettextTranslationFile(BinaryReader reader)
	{
		this.reader = reader;
		readHeader();
	}
	
	public static GettextTranslationFile create(String filePath)
	{
		return create(new File(filePath));
	}
	
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
				long version = reader.readNextUnsignedInt();
				if (version == 0)
					ok = true;
				else
					System.out.println(String.format("ERROR Only version 0 is supported. Got: %d", version));
			} catch (IOException e) {
				System.out.println("ERROR Could not read version");
			}
		}
			
		if (ok)
			return new GettextTranslationFile(reader);
		
		try {
			reader.getByteProvider().close();
			//inStream.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
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
	
	@Override
	public String getInformation() {
		return getString(getInfo(translationsOffset));
	}
	
	@Override
	public String getTranslation(String msgId) {
		long index = findMessage(msgId);
		if (index == -1)
			return null;
		return getString(getInfo(translationsOffset + 8 * index));
	}

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
