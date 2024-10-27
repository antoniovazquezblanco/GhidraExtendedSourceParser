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

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * This plugin adds a some user friendly way to parse samll source code snippets
 * into data types.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Parse source code snippets into data types.",
	description = "This plugin adds a some user friendly way to parse samll source code snippets into data types."
)
//@formatter:on
public class GhidraExtendedSourceParserPlugin extends ProgramPlugin {
	private final static String GROUP_NAME = "extended_source_parser";

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraExtendedSourceParserPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		createActions();
	}

	/**
	 * Create the action objects for this plugin.
	 */
	private void createActions() {
		tool.setMenuGroup(new String[] { "Parse" }, GROUP_NAME);
		tool.addAction(new ParseDataTypeFromSourceAction(this));
	}
}
