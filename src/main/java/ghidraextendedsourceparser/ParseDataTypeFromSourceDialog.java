/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidraextendedsourceparser;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import docking.ReusableDialogComponentProvider;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class ParseDataTypeFromSourceDialog extends ReusableDialogComponentProvider {

	private DataTypeManager dataTypeManager;
	private Category category;
	private JTextField targetLabel;
	private JTextArea sourceTextArea;

	public ParseDataTypeFromSourceDialog() {
		super("Parse Data Types from C source", false, true, true, true);
		buildMainPanel();
	}

	protected void buildMainPanel() {
		targetLabel = new JTextField();
		targetLabel.setEditable(false);
		targetLabel.setFocusable(false);
		JPanel targetPanel = new JPanel(new BorderLayout());
		targetPanel.setBorder(BorderFactory.createTitledBorder("Target category"));
		targetPanel.add(targetLabel);

		sourceTextArea = new JTextArea();
		JScrollPane sourceTextPane = new JScrollPane(sourceTextArea);
		sourceTextPane.getViewport().setPreferredSize(new Dimension(300, 200));
		JPanel sourcePanel = new JPanel(new BorderLayout());
		sourcePanel.setBorder(BorderFactory.createTitledBorder("Source"));
		sourcePanel.add(sourceTextPane);

		JPanel mainPanel = new JPanel(new BorderLayout(10, 5));
		mainPanel.add(targetPanel, BorderLayout.NORTH);
		mainPanel.add(sourcePanel, BorderLayout.SOUTH);
		addWorkPanel(mainPanel);

		JButton parseButton = new JButton("Parse");
		parseButton.addActionListener(ev -> doParse());
		parseButton.setToolTipText("Parse source and add data types to current program");
		addButton(parseButton);
	}

	public void clearSource() {
		sourceTextArea.setText("");
	}

	public void setCategory(Category category) {
		this.category = category;
		targetLabel.setText(category.getCategoryPathName());
	}

	public void setDataManager(DataTypeManager dataTypeManager) {
		this.dataTypeManager = dataTypeManager;
	}

	private void doParse() {
		CParser cParser = new CParser(dataTypeManager, true, null);
		try {
			cParser.parse(sourceTextArea.getText());
		} catch (ParseException e) {
			Msg.showError(this, this.getComponent(), "Error", e.getMessage());
		}
		Map<String, DataType> declarations = cParser.getDeclarations();
		for (DataType dt : declarations.values())
			moveDataTypeToCategory(dt);

		Map<String, DataType> enums = cParser.getEnums();
		for (DataType dt : enums.values())
			moveDataTypeToCategory(dt);

		Map<String, DataType> funcs = cParser.getFunctions();
		for (DataType dt : funcs.values())
			moveDataTypeToCategory(dt);

		Map<String, DataType> composites = cParser.getComposites();
		for (DataType dt : composites.values())
			moveDataTypeToCategory(dt);

		Map<String, DataType> types = cParser.getTypes();
		for (DataType dt : types.values())
			moveDataTypeToCategory(dt);

		if (cParser.didParseSucceed())
			this.dispose();
	}

	private void moveDataTypeToCategory(DataType dt) {
		int t = dataTypeManager.startTransaction("DataType set category path");
		try {
			dt.setCategoryPath(category.getCategoryPath());
		} catch (DuplicateNameException e) {
			dataTypeManager.remove(dt, getTaskMonitorComponent());
			Msg.showError(this, this.getComponent(), "Error",
					dt.getName() + " conflicts with an existing data type. It will not be created!");
		}
		dataTypeManager.endTransaction(t, true);
	}
}
