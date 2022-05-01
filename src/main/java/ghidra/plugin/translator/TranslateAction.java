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

/**
 * This class implements the "Translate" action,
 * which is the main action of the TranslatorPlugin.
 *
 * This action is context sensitive and it is visible
 * only for strings
 *
 * When performed, it looks for the translation of the string
 * in the catalog. If there is no catalog open,
 * a dialog is shown so that the user can select
 * a translation file. If a translation is found,
 * a new end-of-line comment is created. Otherwise,
 * nothing happens.
 *
 * @author pascom@orange.fr
 */
public class TranslateAction extends ListingContextAction
{
	/** The parent Plugin */
	private Plugin plugin;
	/** The translation catalog */
	private TranslationFile catalog;

	/**
	 * This function creates and initializes a new instance
	 * of the "Translate" action.
	 * @param plugin The parent Plugin
	 */
	public TranslateAction(Plugin plugin)
	{
		super("Translate", plugin.getName());

		this.plugin = plugin;
		this.catalog = null;
	}

	/**
	 * This function is called to check that the action is valid
	 * in the given context. That is to say, there is a string
	 * (which may be an equate) at the given address
	 * in the given program.
	 * @param context The context of the action
	 */
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

	/**
	 * This function is called when the action should be performed.
	 * in the given context. It translate the string at the given address.
	 * @param context The context of the action
	 */
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

	/**
	 * This function translates the given message.
	 * It looks for the message in the catalog,
	 * and adds an end-of-line comment with the string translation
	 * in the given program at the given address,
	 * if the lookup is successful.
	 * @param program The program where to add the comment
	 * @param address The address where to add the comment
	 * @param message The message to translate
	 */
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
