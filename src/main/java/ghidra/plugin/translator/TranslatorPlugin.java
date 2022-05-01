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

import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.DockingUtils;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * This is the main class of GhidraTranslatorPlugin.
 * Currently, it just creates the "Translate" action.
 *
 * @author pascom@orange.fr
 */
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Translate strings",
	description = "Automatically translate strings using GNU gettext interface"
	//servicesRequired = {},
	//servicesProvided = {},
	//eventsConsumed = {}
)
public class TranslatorPlugin extends Plugin
{
	/**
	 * This function creates a new instance of the plugin
	 * and initializes it by creating the plugin actions.
	 * @param tool The tool in which the plugin is loaded.
	 */
	public TranslatorPlugin(PluginTool tool)
	{
		super(tool);
		createActions();
	}

	/**
	 * This function creates the "Translate" action.
	 */
	private void createActions()
	{
		TranslateAction action = new TranslateAction(this);
		action.setPopupMenuData(new MenuData(new String[] {"Translate"}, "Decompile"));
		action.setKeyBindingData(new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_T, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
		tool.addAction(action);
	}
}
