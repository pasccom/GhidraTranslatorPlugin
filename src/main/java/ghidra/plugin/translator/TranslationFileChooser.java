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

import java.awt.Component;

import docking.widgets.filechooser.GhidraFileChooser;

public class TranslationFileChooser extends GhidraFileChooser
{
	public TranslationFileChooser(Component parent)
	{
		super(parent);
	}
}
