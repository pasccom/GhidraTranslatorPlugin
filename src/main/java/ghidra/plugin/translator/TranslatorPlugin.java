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

@PluginInfo(
		status = PluginStatus.UNSTABLE,
		packageName = MiscellaneousPluginPackage.NAME,
		category = PluginCategoryNames.ANALYSIS,
		shortDescription = "Translate strings",
		description = "Translate string using GNU gettext interface"
		//servicesRequired = { ProgramManager.class, DataTypeManagerService.class },
		//servicesProvided = { DataService.class },
		//eventsConsumed = { ProgramActivatedPluginEvent.class }
	)
public class TranslatorPlugin extends Plugin
{
	public TranslatorPlugin(PluginTool tool)
	{
		super(tool);
		createActions();
	}

	private void createActions()
	{
		TranslateAction action = new TranslateAction(this);
		action.setPopupMenuData(new MenuData(new String[] {"Translate"}, "Decompile"));
		action.setKeyBindingData(new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_T, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
		tool.addAction(action);
	}
}
