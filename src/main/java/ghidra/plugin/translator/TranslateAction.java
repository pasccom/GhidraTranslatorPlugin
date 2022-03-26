package ghidra.plugin.translator;


import java.io.File;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;

public class TranslateAction extends ListingContextAction
{
	private Plugin plugin;
	private TranslationFile catalog;
	
	public TranslateAction(Plugin plugin)
	{
		super("Translate", plugin.getName());
		
		this.plugin = plugin;
		this.catalog = null;
	}
	
	@Override
	protected boolean isValidContext(ListingActionContext context)
	{
		final Program program = context.getProgram();
		final Address address = context.getAddress();
		
		Data data = program.getListing().getDataAt(address);
		if (data != null)
			return (data.getValue() instanceof String);
		
		return !program.getEquateTable().getEquates(address).isEmpty();
	}

	@Override
	public void actionPerformed(ListingActionContext context)
	{
		final Program program = context.getProgram();
		final Address address = context.getAddress();
		
		int transactionId = program.startTransaction("Translation");
		
		Data data = program.getListing().getDataAt(address);
		if ((data != null) && (data.getValue() instanceof String))
			translate(program, address, (String) data.getValue());
			
		
		for (Equate e : program.getEquateTable().getEquates(address)) {
			translate(program, address, e.getName());
			
		}
		program.endTransaction(transactionId, true);
	}
	
	private void translate(Program program, Address address, String message)
	{
		if (catalog == null) {
			GhidraFileChooser fileChooser = new GhidraFileChooser(plugin.getTool().getActiveWindow());
			fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			fileChooser.setMultiSelectionEnabled(false);
            fileChooser.setTitle("Choose translation file");
            fileChooser.setApproveButtonToolTipText("Choose selected file");
            
            File catalogFile = fileChooser.getSelectedFile(true);
            if (catalogFile != null) {
	            catalog = GettextTranslationFile.create(catalogFile);
	            if (catalog != null)
	            	System.out.println("INFO Translation information:\n" + catalog.getInformation());
	            else
	            	return;
            }
		}
		
		String translation = catalog.getTranslation(message);
		System.out.println(String.format("DEBUG Translation: %s -> %s", message, translation));
		if (translation != null) {
			program.getListing().getCodeUnitContaining(address).setComment(CodeUnit.EOL_COMMENT, translation);
		} else if (message.startsWith("\"") && message.endsWith("\"")) {
			message = message.substring(1, message.length() - 1);
			translation = catalog.getTranslation(message);
			System.out.println(String.format("DEBUG Translation: %s -> %s", message, translation));
			program.getListing().getCodeUnitContaining(address).setComment(CodeUnit.EOL_COMMENT, translation);
		}
	}
	
}
