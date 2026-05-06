package ghistabs;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.task.TaskMonitor;

/**
 * Provide class-level documentation that describes what this exporter does.
 */
public class StabsExporter extends Exporter {

	/**
	 * Exporter constructor.
	 */
	public StabsExporter() {

		// Name the exporter and associate a file extension with it

		super("My Exporter", "exp", null);
	}

	@Override
	public boolean supportsAddressRestrictedExport() {

		// Return true if addrSet export parameter can be used to restrict export

		return false;
	}

	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws ExporterException, IOException {

		// Perform the export, and return true if it succeeded

		return false;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		List<Option> list = new ArrayList<>();

		// If this exporter has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {

		// If this exporter has custom options, assign their values to the exporter here
	}
}
