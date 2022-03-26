package ghidra.plugin.translator;

public interface TranslationFile
{
	public String getInformation();
	public String getTranslation(String msgId);
}
