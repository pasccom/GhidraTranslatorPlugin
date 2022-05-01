package ghidra.plugin.translator;

/**
 * Interface to be implemented by translation files.
 * 
 * @author pascom@orange.fr
 */
public interface TranslationFile
{
	/**
	 * This function retrieves information on the translation file.
	 * 
	 * Indeed translation file usually store some additional information
	 * such as translation author, translation version, ...
	 * @return Translation file information.
	 */
	public String getInformation();
	/**
	 * This function retrieves the translation for the given message.
	 * @param msgId The message to be translated
	 * @return The translation of the given message.
	 */
	public String getTranslation(String msgId);
}
