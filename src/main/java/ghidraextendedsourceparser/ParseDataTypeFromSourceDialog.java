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

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import docking.ReusableDialogComponentProvider;
import ghidra.program.model.data.Category;

public class ParseDataTypeFromSourceDialog extends ReusableDialogComponentProvider {

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
		targetLabel.setText(category.getCategoryPathName());
	}

	private void doParse() {
		// TODO
	}

}
