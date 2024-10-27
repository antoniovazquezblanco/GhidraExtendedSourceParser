package ghidraextendedsourceparser;

import java.awt.Component;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.CategoryNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class ParseDataTypeFromSourceAction extends DockingAction {

	public ParseDataTypeFromSourceAction(GhidraExtendedSourceParserPlugin plugin) {
		super("Parse Data Types From Source", plugin.getName());
		setPopupMenuData(new MenuData(new String[] { "Parse type from srouce..." }, null, "VeryLast"));
		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		// We can only parse into a single node. If multiple nodes are selected, disable
		// the action...
		if (selectionPaths.length > 1)
			return false;
		// Check if the node is of the expected type for the action...
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		return isEnabledForDataTreeNode(node);
	}

	private boolean isEnabledForDataTreeNode(GTreeNode node) {
		if (node instanceof CategoryNode) {
			CategoryNode categoryNode = (CategoryNode) node;
			return categoryNode.isEnabled();
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypesActionContext dtActionContext = (DataTypesActionContext) context;
		GTree gTree = (GTree) dtActionContext.getContextObject();
		Program program = dtActionContext.getProgram();
		if (program == null) {
			Msg.showError(this, gTree, "Archive Export Failed",
					"A suitable program must be open and activated before\n" + "an archive export may be performed.");
			return;
		}
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		Category category = getCategoryFromTreePath(selectionPaths[0]);
		parseFromSource(gTree, program.getDataTypeManager(), category);
	}

	private Category getCategoryFromTreePath(TreePath path) {
		Object last = path.getLastPathComponent();
		if (last instanceof DataTypeNode) {
			DataTypeNode node = (DataTypeNode) last;
			GTreeNode parent = node.getParent();
			return getCategoryFromTreePath(parent.getTreePath());
		} else if (last instanceof CategoryNode) {
			CategoryNode node = (CategoryNode) last;
			return node.getCategory();
		}
		return null;
	}

	/**
	 * Asks the user to input some source code. Attempts to parse set source code
	 * into valid data types. Writes those data types into the provided category.
	 */
	private void parseFromSource(Component parent, DataTypeManager programDataTypeMgr, Category category) {
		// TODO
	}
}
