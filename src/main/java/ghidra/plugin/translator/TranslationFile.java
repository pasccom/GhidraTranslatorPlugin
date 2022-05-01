/* Copyright 2022 Pascal COMBES <pascom@orange.fr>
 *
 * This file is part of GhidraTranslatorPlugin.
 *
 * GhidraTranslatorPlugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GhidraTranslatorPlugin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GhidraTranslatorPlugin. If not, see <http://www.gnu.org/licenses/>
 */
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
