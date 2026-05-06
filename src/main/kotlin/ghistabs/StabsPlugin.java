package ghistabs;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

import javax.swing.*;
import java.awt.*;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = ExamplesPluginPackage.NAME,
        category = PluginCategoryNames.EXAMPLES,
        shortDescription = "Plugin short description goes here.",
        description = "Plugin long description goes here."
)
public class StabsPlugin extends ProgramPlugin {

    MyProvider provider;

    /**
     * Plugin constructor.
     *
     * @param tool The plugin tool that this plugin is added to.
     */
    public StabsPlugin(PluginTool tool) {
        super(tool);

        // Customize provider (or remove if a provider is not desired)
        String pluginName = getName();
        provider = new MyProvider(this, pluginName);

        // Customize help (or remove if help is not desired)
        String topicName = this.getClass().getPackage().getName();
        String anchorName = "HelpAnchor";
        provider.setHelpLocation(new HelpLocation(topicName, anchorName));
    }

    @Override
    public void init() {
        super.init();

        // Acquire services if necessary
    }

    // If provider is desired, it is recommended to move it to its own file
    private static class MyProvider extends ComponentProvider {

        private JPanel panel;
        private DockingAction action;

        public MyProvider(Plugin plugin, String owner) {
            super(plugin.getTool(), "Stabs Provider", owner);
            buildPanel();
            createActions();
        }

        // Customize GUI
        private void buildPanel() {
            panel = new JPanel(new BorderLayout());
            JTextArea textArea = new JTextArea(5, 25);
            textArea.setEditable(false);
            panel.add(new JScrollPane(textArea));
            setVisible(true);
        }

        // Customize actions
        private void createActions() {
            action = new DockingAction("My Action", getOwner()) {
                @Override
                public void actionPerformed(ActionContext context) {
                    Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
                }
            };
            action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
            action.setEnabled(true);
            action.markHelpUnnecessary();
            dockingTool.addLocalAction(this, action);
        }

        @Override
        public JComponent getComponent() {
            return panel;
        }
    }
}
