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
