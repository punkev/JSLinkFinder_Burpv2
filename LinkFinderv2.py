#
#  BurpLinkFinder - Find links and dynamic content within JS files.
#
#  Copyright (c) 2025 Kevin Dsouza
#  Based on original work: Copyright (c) 2022 Frans Hendrik Botes
#  Dynamic scanning logic and UI enhancements by Gemini
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
import cgi
from os import path
from javax import swing
from java.awt import Font, Color
from threading import Thread
from jarray import array
from java.awt import EventQueue
from java.lang import Runnable
from java.awt.event import MouseAdapter
from javax.swing import JFileChooser, JScrollPane, JSplitPane, JTabbedPane, JTable, JPopupMenu, JMenuItem
from javax.swing import JPanel, JLabel, JCheckBox, JTextField, JTextArea, GroupLayout, BorderFactory
from javax.swing.event import DocumentListener
from javax.swing import SwingUtilities
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from javax.swing.table import TableRowSorter
from javax.swing import RowFilter
from java.awt import Insets
import urlparse,threading
try:
    import queue
except ImportError:
    import Queue as queue

# --- Pre-defined regex patterns for ease of use ---
PREDEFINED_REGEXES = [
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Stripe API Key", r"(sk|pk)_(test|live)_[a-zA-Z0-9]{24}"),
    ("Amazon S3 Bucket", r"[a-zA-Z0-9.-]+\.s3\.amazonaws\.com"),
    ("JSON Web Token (JWT)", r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
    ("Internal IP Address", r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"),
    ("Bearer Token", r"[Bb]earer\s+[a-zA-Z0-9\._-]{20,}")
]
# Default params, now editable in UI
JSExclusionList = ['jquery', 'google-analytics','gpt.js','modernizr','gtm','fbevents']

class Run(Runnable):
    def __init__(self, runner): self.runner = runner
    def run(self): self.runner()

class FilterListener(DocumentListener):
    def __init__(self, extender, table_model, filter_text_field):
        self.extender = extender
        self.table_model = table_model
        self.filter_text_field = filter_text_field
    def insertUpdate(self, e): self.extender.apply_filter(self.table_model, self.filter_text_field)
    def removeUpdate(self, e): self.extender.apply_filter(self.table_model, self.filter_text_field)
    def changedUpdate(self, e): self.extender.apply_filter(self.table_model, self.filter_text_field)

class FinderTableModel(AbstractTableModel):
    def __init__(self, columns, initial_data=[]):
        self.columns = columns
        self.data = list(initial_data)
    def getRowCount(self): return len(self.data)
    def getColumnCount(self): return len(self.columns)
    def getColumnName(self, col): return self.columns[col]
    def getValueAt(self, row, col): return self.data[row][col]
    def isCellEditable(self, row, col): return False
    def addRow(self, row_data):
        self.data.append(row_data)
        self.fireTableRowsInserted(self.getRowCount() - 1, self.getRowCount() - 1)
    def clear(self):
        del self.data[:]
        self.fireTableDataChanged()

class StatusCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = super(StatusCellRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
        default_font = table.getFont()
        component.setFont(default_font)
        component.setForeground(table.getForeground() if not isSelected else table.getSelectionForeground())
        val_str = str(value)
        if "-- No links found --" in val_str:
            component.setForeground(Color.RED)
            component.setFont(default_font.deriveFont(Font.BOLD))
        elif "Links found in:" in val_str:
            component.setFont(default_font.deriveFont(Font.BOLD))
        return component

class TableMouseListener(MouseAdapter):
    def __init__(self, table, extender):
        self._table = table
        self._extender = extender
    def mouseReleased(self, e):
        if e.isPopupTrigger():
            row = self._table.rowAtPoint(e.getPoint())
            if row >= 0 and row < self._table.getRowCount():
                self._table.setRowSelectionInterval(row, row)
                self._extender.showContextMenu(e)
            else:
                self._table.clearSelection()

class BurpExtender(IBurpExtender, IScannerCheck, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS LinkFinder V2")
        callbacks.issueAlert("JS LinkFinder V2 Passive Scanner enabled")
        callbacks.registerScannerCheck(self)
        self.processed_dynamic_files = set()
        self.dynamic_js_queue = queue.Queue()
        self.links_found_counter = 0 
        self.compiled_static_regexes = []
        self.compiled_static_regexes.append((re.compile(linkAnalyse.default_regex_str, re.VERBOSE), "default"))
        for _, pattern in PREDEFINED_REGEXES: self.compiled_static_regexes.append((re.compile(pattern), "custom"))
        self.initUI()
        callbacks.addSuiteTab(self)
        self.callbacks.printOutput("JS LinkFinder V2 loaded.")
        for _ in range(5):
            thread = threading.Thread(target=self.process_dynamic_js_queue)
            thread.daemon = True
            thread.start()

    def initUI(self):
        self._parentPane = JTabbedPane()
        self.initMainPanel()
        self.initDynamicJSPanel()
        self.initSettingsPanel()
        self._parentPane.addTab("Main", self._splitpane)
        self._parentPane.addTab("Dynamic JS", self.dynamicLogPanel)
        self._parentPane.addTab("Settings", self.settingsPanel)
        
    def initMainPanel(self):
        self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT); self._splitpane.setDividerLocation(800)
        self._splitpane2 = JSplitPane(JSplitPane.VERTICAL_SPLIT); self._splitpane2.setDividerLocation(300)
        self.logPanel = JPanel()
        self.logModel = FinderTableModel(["Link / Finding", "JS File Source", "Type"])
        self.logTable = JTable(self.logModel)
        self.logTable.getColumnModel().getColumn(0).setCellRenderer(StatusCellRenderer())
        self.logTable.addMouseListener(TableMouseListener(self.logTable, self))
        self.logSorter = TableRowSorter(self.logModel); self.logTable.setRowSorter(self.logSorter)
        self.logTable.setFont(Font("Consolas", Font.PLAIN, 12))
        self.logPane = JScrollPane(self.logTable)
        self.filterLabel = JLabel("Filter:"); self.filterTextField = JTextField("", 30)
        self.filterTextField.getDocument().addDocumentListener(FilterListener(self, self.logSorter, self.filterTextField))
        self.clearBtn = swing.JButton("Clear", actionPerformed=self.clear_main_log)
        self.exportBtn = swing.JButton("Export", actionPerformed=self.exportLog)
        self.filePanel = JPanel()
        self.fileModel = FinderTableModel(["Filename"])
        self.fileTable = JTable(self.fileModel)
        self.fileSorter = TableRowSorter(self.fileModel); self.fileTable.setRowSorter(self.fileSorter)
        self.fileTable.setFont(Font("Consolas", Font.PLAIN, 12))
        self.filePane = JScrollPane(self.fileTable)
        self.fileFilterLabel = JLabel("Filter:"); self.fileFilterTextField = JTextField("", 30)
        self.fileFilterTextField.getDocument().addDocumentListener(FilterListener(self, self.fileSorter, self.fileFilterTextField))
        self.clearFilesBtn = swing.JButton("Clear", actionPerformed=lambda e: self.fileModel.clear())
        self.mapPanel = JPanel()
        self.mapModel = FinderTableModel(["URL"])
        self.mapTable = JTable(self.mapModel)
        self.mapSorter = TableRowSorter(self.mapModel); self.mapTable.setRowSorter(self.mapSorter)
        self.mapTable.setFont(Font("Consolas", Font.PLAIN, 12))
        self.mapPane = JScrollPane(self.mapTable)
        self.mapFilterLabel = JLabel("Filter:"); self.mapFilterTextField = JTextField("", 30)
        self.mapFilterTextField.getDocument().addDocumentListener(FilterListener(self, self.mapSorter, self.mapFilterTextField))
        self.clearMapBtn = swing.JButton("Clear", actionPerformed=lambda e: self.mapModel.clear())
        self.mapMapBtn = swing.JButton("Map to SiteMap", actionPerformed=self.mapMaps)
        self._splitpane.setLeftComponent(self.logPanel)
        self._splitpane2.setTopComponent(self.filePanel); self._splitpane2.setBottomComponent(self.mapPanel)
        self._splitpane.setRightComponent(self._splitpane2)
        self.setupMainLayouts()

    def clear_main_log(self, event):
        self.logModel.clear()
        self.links_found_counter = 0

    def showContextMenu(self, event):
        menu = JPopupMenu()
        source_table = event.getComponent()

        if source_table == self.logTable:
            repeater_item = JMenuItem("Send to Repeater")
            intruder_item = JMenuItem("Send to Intruder")
            selected_row_index = self.logTable.getSelectedRow()
            finding_type = self.logModel.getValueAt(selected_row_index, 2)
            if finding_type == "STATUS":
                repeater_item.setEnabled(False)
                intruder_item.setEnabled(False)
            repeater_item.addActionListener(lambda e: self.sendRequest("repeater"))
            intruder_item.addActionListener(lambda e: self.sendRequest("intruder"))
            menu.add(repeater_item)
            menu.add(intruder_item)
        
        elif source_table == self.dynamicLogTable:
            repeater_item = JMenuItem("Send to Repeater")
            intruder_item = JMenuItem("Send to Intruder")
            repeater_item.addActionListener(lambda e: self.sendDynamicRequest("repeater"))
            intruder_item.addActionListener(lambda e: self.sendDynamicRequest("intruder"))
            menu.add(repeater_item)
            menu.add(intruder_item)

        menu.show(source_table, event.getX(), event.getY())

    def sendRequest(self, tool):
        selected_row_index = self.logTable.getSelectedRow()
        if selected_row_index == -1: return
        found_link = self.logModel.getValueAt(selected_row_index, 0)
        js_source_url = self.logModel.getValueAt(selected_row_index, 1)
        if not js_source_url:
            for i in range(selected_row_index, -1, -1):
                if self.logModel.getValueAt(i, 2) == "STATUS":
                    js_source_url = self.logModel.getValueAt(i, 1)
                    break
        if not js_source_url:
            self.callbacks.printError("Could not find the JS source URL for the selected link.")
            return
        try:
            full_url_str = urlparse.urljoin(js_source_url, found_link)
            full_url_obj = URL(full_url_str)
            host = full_url_obj.getHost()
            port = full_url_obj.getPort() if full_url_obj.getPort() != -1 else full_url_obj.getDefaultPort()
            is_https = full_url_obj.getProtocol().lower() == 'https'
            request_bytes = self.helpers.buildHttpRequest(full_url_obj)
            if tool == "repeater":
                self.callbacks.sendToRepeater(host, port, is_https, request_bytes, "LinkFinder: " + path.basename(full_url_obj.getPath()))
            elif tool == "intruder":
                self.callbacks.sendToIntruder(host, port, is_https, request_bytes)
        except Exception as e:
            self.callbacks.printError("Error sending to {}: {}".format(tool, str(e)))

    def sendDynamicRequest(self, tool):
        selected_row_index = self.dynamicLogTable.getSelectedRow()
        if selected_row_index == -1: return
        url_str = self.dynamicLogModel.getValueAt(selected_row_index, 0)
        try:
            full_url_obj = URL(url_str)
            host = full_url_obj.getHost()
            port = full_url_obj.getPort() if full_url_obj.getPort() != -1 else full_url_obj.getDefaultPort()
            is_https = full_url_obj.getProtocol().lower() == 'https'
            request_bytes = self.helpers.buildHttpRequest(full_url_obj)
            if tool == "repeater":
                self.callbacks.sendToRepeater(host, port, is_https, request_bytes, "LinkFinder: " + path.basename(full_url_obj.getPath()))
            elif tool == "intruder":
                self.callbacks.sendToIntruder(host, port, is_https, request_bytes)
        except Exception as e:
            self.callbacks.printError("Error sending dynamic URL to {}: {}".format(tool, str(e)))

    def initDynamicJSPanel(self):
        self.dynamicLogPanel = JPanel()
        # MODIFIED: Updated column names for the Dynamic JS tab
        self.dynamicLogModel = FinderTableModel(["Generated URL", "Source File", "Reason"])
        self.dynamicLogTable = JTable(self.dynamicLogModel)
        self.dynamicLogTable.addMouseListener(TableMouseListener(self.dynamicLogTable, self))
        self.dynamicLogSorter = TableRowSorter(self.dynamicLogModel); self.dynamicLogTable.setRowSorter(self.dynamicLogSorter)
        self.dynamicLogTable.setFont(Font("Consolas", Font.PLAIN, 12))
        # MODIFIED: Adjusted column widths for the new layout
        self.dynamicLogTable.getColumnModel().getColumn(0).setPreferredWidth(400)
        self.dynamicLogTable.getColumnModel().getColumn(1).setPreferredWidth(400)
        self.dynamicLogTable.getColumnModel().getColumn(2).setPreferredWidth(150)
        dynamicLogPane = JScrollPane(self.dynamicLogTable)
        dynamicFilterLabel = JLabel("Filter:"); dynamicFilterTextField = JTextField("", 30)
        dynamicFilterTextField.getDocument().addDocumentListener(FilterListener(self, self.dynamicLogSorter, dynamicFilterTextField))
        clearDynamicBtn = swing.JButton("Clear", actionPerformed=lambda e: self.dynamicLogModel.clear())
        layout = GroupLayout(self.dynamicLogPanel); self.dynamicLogPanel.setLayout(layout)
        layout.setAutoCreateGaps(True); layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(layout.createParallelGroup().addComponent(dynamicLogPane).addGroup(layout.createSequentialGroup().addComponent(dynamicFilterLabel).addComponent(dynamicFilterTextField).addGap(0, 0, GroupLayout.PREFERRED_SIZE).addComponent(clearDynamicBtn)))
        layout.setVerticalGroup(layout.createSequentialGroup().addComponent(dynamicLogPane).addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE).addComponent(dynamicFilterLabel).addComponent(dynamicFilterTextField).addComponent(clearDynamicBtn)))

    def setupMainLayouts(self):
        layout = GroupLayout(self.logPanel); self.logPanel.setLayout(layout)
        layout.setAutoCreateGaps(True); layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(layout.createParallelGroup().addComponent(self.logPane).addGroup(layout.createSequentialGroup().addComponent(self.filterLabel).addComponent(self.filterTextField).addGap(0, 0, GroupLayout.PREFERRED_SIZE).addComponent(self.clearBtn).addComponent(self.exportBtn)))
        layout.setVerticalGroup(layout.createSequentialGroup().addComponent(self.logPane).addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE).addComponent(self.filterLabel).addComponent(self.filterTextField).addComponent(self.clearBtn).addComponent(self.exportBtn)))
        layoutf = GroupLayout(self.filePanel); self.filePanel.setLayout(layoutf)
        layoutf.setAutoCreateGaps(True); layoutf.setAutoCreateContainerGaps(True)
        layoutf.setHorizontalGroup(layoutf.createParallelGroup().addComponent(self.filePane).addGroup(layoutf.createSequentialGroup().addComponent(self.fileFilterLabel).addComponent(self.fileFilterTextField).addGap(0, 0, GroupLayout.PREFERRED_SIZE).addComponent(self.clearFilesBtn)))
        layoutf.setVerticalGroup(layoutf.createSequentialGroup().addComponent(self.filePane).addGroup(layoutf.createParallelGroup(swing.GroupLayout.Alignment.BASELINE).addComponent(self.fileFilterLabel).addComponent(self.fileFilterTextField).addComponent(self.clearFilesBtn)))
        layoutm = GroupLayout(self.mapPanel); self.mapPanel.setLayout(layoutm)
        layoutm.setAutoCreateGaps(True); layoutm.setAutoCreateContainerGaps(True)
        layoutm.setHorizontalGroup(layoutm.createParallelGroup().addComponent(self.mapPane).addGroup(layoutm.createSequentialGroup().addComponent(self.mapFilterLabel).addComponent(self.mapFilterTextField).addGap(0, 0, GroupLayout.PREFERRED_SIZE).addComponent(self.clearMapBtn).addComponent(self.mapMapBtn)))
        layoutm.setVerticalGroup(layoutm.createSequentialGroup().addComponent(self.mapPane).addGroup(layoutm.createParallelGroup(swing.GroupLayout.Alignment.BASELINE).addComponent(self.mapFilterLabel).addComponent(self.mapFilterTextField).addComponent(self.clearMapBtn).addComponent(self.mapMapBtn)))

    def initSettingsPanel(self):
        self.settingsPanel = JPanel()
        self.scopeCheckBox = JCheckBox("Only scan items in target scope")
        self.exclusionLabel = JLabel("Exclusion List (one item per line):")
        self.exclusionTextArea = JTextArea(5, 30); self.exclusionTextArea.setText("\n".join(JSExclusionList))
        exclusionScrollPane = JScrollPane(self.exclusionTextArea)
        self.predefinedLabel = JLabel("Pre-defined Patterns (Enable/Disable):")
        self.predefined_checkboxes = []
        predefinedPanel = JPanel(); predefinedLayout = GroupLayout(predefinedPanel); predefinedPanel.setLayout(predefinedLayout)
        hGroup = predefinedLayout.createParallelGroup(); vGroup = predefinedLayout.createSequentialGroup()
        for description, pattern in PREDEFINED_REGEXES:
            checkbox = JCheckBox(description); self.predefined_checkboxes.append((checkbox, pattern))
            hGroup.addComponent(checkbox); vGroup.addComponent(checkbox)
        predefinedLayout.setHorizontalGroup(hGroup); predefinedLayout.setVerticalGroup(vGroup)
        self.regexLabel = JLabel("Your Custom Regex Patterns (one per line):")
        self.regexTextArea = JTextArea(8, 30); regexScrollPane = JScrollPane(self.regexTextArea)
        layout = GroupLayout(self.settingsPanel); self.settingsPanel.setLayout(layout)
        layout.setAutoCreateGaps(True); layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(layout.createParallelGroup().addComponent(self.scopeCheckBox).addComponent(self.exclusionLabel).addComponent(exclusionScrollPane).addComponent(self.predefinedLabel).addComponent(predefinedPanel).addComponent(self.regexLabel).addComponent(regexScrollPane))
        layout.setVerticalGroup(layout.createSequentialGroup().addComponent(self.scopeCheckBox).addComponent(self.exclusionLabel).addComponent(exclusionScrollPane).addComponent(self.predefinedLabel).addComponent(predefinedPanel).addComponent(self.regexLabel).addComponent(regexScrollPane))

    def getTabCaption(self): return "JS LinkFinder V2"
    def getUiComponent(self): return self._parentPane
    def exportLog(self, event):
        fc = JFileChooser()
        if fc.showSaveDialog(self.logPanel) == JFileChooser.APPROVE_OPTION:
            with open(fc.getSelectedFile().getCanonicalPath(), 'w') as f:
                for row_index in range(self.logTable.getRowCount()):
                    row_data = [str(self.logTable.getValueAt(row_index, col)) for col in range(self.logTable.getColumnCount())]
                    f.write("\t".join(row_data) + "\n")
            
    def apply_filter(self, sorter, text_field):
        filter_text = text_field.getText()
        sorter.setRowFilter(RowFilter.regexFilter("(?i)" + re.escape(filter_text))) if filter_text else sorter.setRowFilter(None)

    def doPassiveScan(self, ihrr):
        try:
            urlReq = ihrr.getUrl()
            if self.scopeCheckBox.isSelected() and not self.callbacks.isInScope(urlReq): return None
            
            responseBytes = ihrr.getResponse()
            if not responseBytes: return None

            urlStr = str(urlReq)
            responseInfo = self.helpers.analyzeResponse(responseBytes)
            
            is_js_url = urlStr.split('?')[0].lower().endswith('.js')
            stated_mime = responseInfo.getStatedMimeType().lower()
            inferred_mime = responseInfo.getInferredMimeType().lower()

            if is_js_url or 'script' in stated_mime or 'javascript' in inferred_mime:
                if urlStr not in self.processed_dynamic_files:
                    self.processed_dynamic_files.add(urlStr)
                    self.dynamic_js_queue.put((urlStr, responseBytes))
                
                exclusions = [e.strip() for e in self.exclusionTextArea.getText().splitlines() if e.strip()]
                if any(x in urlStr for x in exclusions): return None
                
                enabled_patterns = [p for cb, p in self.predefined_checkboxes if cb.isSelected()]
                user_patterns = [p.strip() for p in self.regexTextArea.getText().splitlines() if p.strip()]
                
                linkA = linkAnalyse(ihrr, self.callbacks, self.helpers, user_patterns, enabled_patterns, self.compiled_static_regexes)
                issueText = linkA.analyseURL()
                
                if not issueText:
                    message = "-- No links found --"
                    SwingUtilities.invokeLater(Run(lambda: self.logModel.addRow([message, urlStr, "STATUS"])))
                else:
                    self.links_found_counter += 1
                    message = "({}) [+] {} Links found in:".format(self.links_found_counter, len(issueText))
                    SwingUtilities.invokeLater(Run(lambda: self.logModel.addRow([message, urlStr, "STATUS"])))

                    links, full_urls, highlights = [], [], []
                    for item in issueText:
                        link, source = item['link'], item['source']
                        SwingUtilities.invokeLater(Run(lambda: self.logModel.addRow([link, "", source.upper()])))
                        
                        full_url = urlparse.urljoin(urlStr, link) if not link.lower().startswith(('http:', 'https:')) else link
                        if full_url and self.mapModel.data.count([full_url]) == 0:
                            SwingUtilities.invokeLater(Run(lambda: self.mapModel.addRow([full_url])))
                            if full_url not in full_urls: full_urls.append(full_url)
                        if link not in links: links.append(link)
                        if [item['start'], item['end']] not in highlights: highlights.append([item['start'], item['end']])
                        filNam = path.basename(link.split('?')[0].split('#')[0])
                        if linkA.isNotBlank(filNam) and linkA.checkValidFile(filNam) and self.fileModel.data.count([filNam]) == 0:
                            SwingUtilities.invokeLater(Run(lambda: self.fileModel.addRow([filNam])))
                    
                    if links:
                        issues = ArrayList()
                        issues.add(SRI(ihrr, self.helpers, self.callbacks, links, full_urls, highlights))
                        return issues
                        
        except Exception as e:
            self.callbacks.printError("Error in doPassiveScan: " + str(e))
        
        return None
        
    def consolidateDuplicateIssues(self, isb, isa): return -1
    def extensionUnloaded(self): self.callbacks.printOutput("JS LinkFinder V2 unloaded")

    def mapMaps(self, event):
        self.q = queue.Queue()
        urls_list = [row[0] for row in self.mapModel.data]
        for url in list(set(urls_list)):
            if url: self.q.put(url.strip())
        if not self.q.empty():
            self.callbacks.printOutput("Mapping {} URLs...".format(self.q.qsize()))
            for _ in range(10): threading.Thread(target=self.ProcessQueue).start()
        else: self.callbacks.printOutput("No URLs to map.")

    def ProcessQueue(self):
        while not self.q.empty():
            try:
                url = self.q.get(timeout=1); self.ProcessURL(url); self.q.task_done()
            except queue.Empty: break
            except Exception as e: self.callbacks.printError("ProcessQueue Error: " + str(e))

    def ProcessURL(self,url):
        try:
            if url.startswith('http'):
                url_obj = URL(url)
                service = self.helpers.buildHttpService(url_obj.getHost(), url_obj.getPort(), url_obj.getProtocol() == 'https')
                req = self.helpers.buildHttpRequest(url_obj)
                resp = self.callbacks.makeHttpRequest(service, req)
                if resp: self.callbacks.addToSiteMap(resp)
        except Exception as e: self.callbacks.printError("ProcessURL Error for {}: {}".format(url, str(e)))

    def process_dynamic_js_queue(self):
        while True:
            try:
                url_string, response_bytes = self.dynamic_js_queue.get(timeout=5)
                self.check_js_content(url_string, response_bytes)
                self.dynamic_js_queue.task_done()
            except queue.Empty: continue
            except Exception as e: self.callbacks.printError("Dynamic JS Queue Error: " + str(e))
                
    def check_js_content(self, url_string, response_bytes):
        """
        MODIFIED: This function now parses the webpack map to generate URLs.
        """
        try:
            if not response_bytes: return

            body_string = self.helpers.bytesToString(response_bytes[self.helpers.analyzeResponse(response_bytes).getBodyOffset():])

            # Step 1: Find the specific webpack map pattern
            map_match = re.search(r'__webpack_require__\.u=\w=>\w\+"\."\+({.+?})\[\w\]', body_string)
        
            if map_match:
                map_string = map_match.group(1)
            
                # Step 2: Extract all ID/Hash pairs from the map
                pairs = re.findall(r'([0-9]+):"([a-fA-F0-9]+)"', map_string)
            
                if pairs:
                    # Get the directory of the source JS file to build relative paths
                    base_url = urlparse.urljoin(url_string, '.') 
                
                    # Step 3: Construct and log each potential URL
                    for chunk_id, hash_val in pairs:
                        chunk_filename = "{}.{}.js".format(chunk_id, hash_val)
                        full_url = urlparse.urljoin(base_url, chunk_filename)
                        
                        # Use a lambda that captures the variables to avoid issues in the loop
                        def add_row_action(url=full_url, source=url_string):
                           self.dynamicLogModel.addRow([url, source, "Webpack Map Parse"])
                        
                        SwingUtilities.invokeLater(Run(add_row_action))

        except Exception as e:
            self.callbacks.printError("Error parsing webpack map in {}: {}".format(url_string, str(e)))

class linkAnalyse():
    default_regex_str = r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/.]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|/][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"|']{0,}|)))(?:"|')"""
    def __init__(self, reqres, callbacks, helpers, custom_regex_strs, enabled_predefined_strs, compiled_static_regexes):
        self.callbacks, self.helpers, self.reqres = callbacks, helpers, reqres
        self.custom_regex_strs = custom_regex_strs
        self.compiled_static_regexes = compiled_static_regexes
    def parser_file(self, content):
        items = []
        for compiled_regex, source in self.compiled_static_regexes:
            for m in compiled_regex.finditer(content):
                match_text = m.group(1) if source == "default" and m.groups() else (m.group(1) if m.groups() else m.group(0))
                items.append({"link": match_text.strip('\'"'), "start": m.start(0), "end": m.end(0), "source": source})
        for r_str in self.custom_regex_strs:
            try:
                custom_regex = re.compile(r_str)
                for m in custom_regex.finditer(content):
                    match_text = m.group(1) if m.groups() else m.group(0)
                    items.append({"link": match_text.strip('\'"'), "start": m.start(0), "end": m.end(0), "source": "custom"})
            except re.error as e: self.callbacks.printError("Invalid custom regex '{}': {}".format(r_str, str(e)))
        all_links, no_dup_items = set(), []
        for item in items:
            if item["link"] not in all_links:
                all_links.add(item["link"]); no_dup_items.append(item)
        return no_dup_items
    def analyseURL(self):
        resp_bytes = self.reqres.getResponse()
        if not resp_bytes: return []
        return self.parser_file(self.helpers.bytesToString(resp_bytes))
    def checkValidFile(self,f): return bool(re.search(r"^[a-zA-Z0-9._-]+$", f)) if f else False
    def isNotBlank(self,s): return bool(s and s.strip())

class SRI(IScanIssue):
    def __init__(self, reqres, helpers, callbacks, links, full_urls, highlights):
        self.helpers, self.callbacks = helpers, callbacks
        self.links, self.full_urls = sorted(list(set(links))), sorted(list(set(full_urls)))
        markers = ArrayList()
        for h in highlights: markers.add(array([h[0],h[1]],'i'))
        self.reqres = self.callbacks.applyMarkers(reqres, None, markers)
        self.issue_detail = "Burp Scanner has discovered the following values in this JS file:<ul>"
        self.issue_detail += "".join("<li>{}</li>".format(cgi.escape(l)) for l in self.links) + "</ul>"
        if self.full_urls:
             self.issue_detail += "The following full URLs were resolved:<ul>"
             self.issue_detail += "".join("<li>{}</li>".format(cgi.escape(u)) for u in self.full_urls) + "</ul>"
    def getHost(self): return self.reqres.getHost()
    def getPort(self): return self.reqres.getPort()
    def getProtocol(self): return self.reqres.getProtocol()
    def getUrl(self): return self.reqres.getUrl()
    def getIssueName(self): return "Linkfinder Discovered Values in JS File"
    def getIssueType(self): return 0x08000000
    def getSeverity(self): return "Information"
    def getConfidence(self): return "Certain"
    def getIssueBackground(self): return "JS files may contain links, API keys, or other sensitive information."
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self.issue_detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return [self.reqres]
    def getHttpService(self): return self.reqres.getHttpService()

# --- END OF SCRIPT ---