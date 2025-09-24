#
#  BurpLinkFinder - Find links within JS files.
#
#  Copyright (c) 2022 Frans Hendrik Botes
#  Copyright (c) 2025 Kevin Dsouza
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
from javax.swing import JFileChooser, JScrollPane, JSplitPane, JTabbedPane
from javax.swing import JPanel, JLabel, JCheckBox, JTextField, JTextArea
from javax.swing.event import DocumentListener
from javax.swing import SwingUtilities
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
    def __init__(self, extender): self.extender = extender
    def insertUpdate(self, e): self.extender.apply_filter()
    def removeUpdate(self, e): self.extender.apply_filter()
    def changedUpdate(self, e): self.extender.apply_filter()

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSLinkFinderv2")
        callbacks.issueAlert("BurpJSLinkFinderv2 Passive Scanner enabled")
        callbacks.registerScannerCheck(self)
        self.threads = []
        
        # Master lists to hold all data
        self.all_log_entries = [
            "BurpJS LinkFinder loaded.",
            "Copyright (c) 2022 Frans Hendrik Botes",
            "Copyright (c) 2025 Kevin Dsouza"
        ]
        self.all_filenames = []
        self.all_mapped_urls = []

        self.initUI()
        callbacks.addSuiteTab(self)
        callbacks.printOutput("BurpJS LinkFinder v2 loaded.")
        callbacks.printOutput("Copyright (c) 2022 Frans Hendrik Botes")
        callbacks.printOutput("Copyright (c) 2025 Kevin Dsouza")
        self.outputTxtArea.setText("\n".join(self.all_log_entries))

    def initUI(self):
        self._parentPane = JTabbedPane()
        self.initMainPanel()
        self.initSettingsPanel()
        self._parentPane.addTab("Main", self._splitpane)
        self._parentPane.addTab("Settings", self.settingsPanel)
        
    def initMainPanel(self):
        self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._splitpane.setDividerLocation(800)
        self._splitpane2 = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane2.setDividerLocation(300)

        # Log Output Panel
        self.logPanel = JPanel()
        self.outputLabel = JLabel("LinkFinder Log:")
        self.filterLabel = JLabel("Filter:")
        self.filterTextField = JTextField("", 30)
        self.filterTextField.getDocument().addDocumentListener(FilterListener(self))
        self.outputTxtArea = JTextArea()
        self.logPane = JScrollPane(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export", actionPerformed=self.exportLog)
        
        # Filenames Panel
        self.filePanel = JPanel()
        self.fileNamesLabel = JLabel("Filenames:")
        self.fileFilterLabel = JLabel("Filter:")
        self.fileFilterTextField = JTextField("", 30)
        self.fileFilterTextField.getDocument().addDocumentListener(FilterListener(self))
        self.filesTxtArea = JTextArea()
        self.filesPane = JScrollPane(self.filesTxtArea)
        self.clearFilesBtn = swing.JButton("Clear", actionPerformed=self.clearFilesLog)
        
        # Mapped URLs Panel
        self.mapPanel = JPanel()
        self.mapLabel = JLabel("Mapped URLs:")
        self.mapFilterLabel = JLabel("Filter:")
        self.mapFilterTextField = JTextField("", 30)
        self.mapFilterTextField.getDocument().addDocumentListener(FilterListener(self))
        self.mapTxtArea = JTextArea()
        self.mapPane = JScrollPane(self.mapTxtArea)
        self.clearMapBtn = swing.JButton("Clear", actionPerformed=self.clearMAPLog)
        self.mapMapBtn = swing.JButton("Map to SiteMap", actionPerformed=self.mapMaps)
        
        # Common settings for text areas - FONT SIZE INCREASED HERE
        for area in [self.outputTxtArea, self.filesTxtArea, self.mapTxtArea]:
            area.setFont(Font("Consolas", Font.PLAIN, 12))
            area.setEditable(False)
        
        # Add components to panes
        self._splitpane.setLeftComponent(self.logPanel)
        self._splitpane2.setTopComponent(self.filePanel)
        self._splitpane2.setBottomComponent(self.mapPanel)
        self._splitpane.setRightComponent(self._splitpane2)

        # Full layout definitions
        self.setupLayouts()

    def setupLayouts(self):
        # Log Panel Layout
        layout = swing.GroupLayout(self.logPanel)
        self.logPanel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addComponent(self.outputLabel)
            .addGroup(layout.createSequentialGroup().addComponent(self.filterLabel).addComponent(self.filterTextField))
            .addComponent(self.logPane)
            .addGroup(layout.createSequentialGroup().addComponent(self.clearBtn).addComponent(self.exportBtn)))
        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.outputLabel)
            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE).addComponent(self.filterLabel).addComponent(self.filterTextField))
            .addComponent(self.logPane)
            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE).addComponent(self.clearBtn).addComponent(self.exportBtn)))

        # File Panel Layout
        layoutf = swing.GroupLayout(self.filePanel)
        self.filePanel.setLayout(layoutf)
        layoutf.setAutoCreateGaps(True)
        layoutf.setAutoCreateContainerGaps(True)
        layoutf.setHorizontalGroup(
            layoutf.createParallelGroup()
            .addComponent(self.fileNamesLabel)
            .addGroup(layoutf.createSequentialGroup().addComponent(self.fileFilterLabel).addComponent(self.fileFilterTextField))
            .addComponent(self.filesPane)
            .addComponent(self.clearFilesBtn))
        layoutf.setVerticalGroup(
            layoutf.createSequentialGroup()
            .addComponent(self.fileNamesLabel)
            .addGroup(layoutf.createParallelGroup(swing.GroupLayout.Alignment.BASELINE).addComponent(self.fileFilterLabel).addComponent(self.fileFilterTextField))
            .addComponent(self.filesPane)
            .addComponent(self.clearFilesBtn))
        
        # Map Panel Layout
        layoutm = swing.GroupLayout(self.mapPanel)
        self.mapPanel.setLayout(layoutm)
        layoutm.setAutoCreateGaps(True)
        layoutm.setAutoCreateContainerGaps(True)
        layoutm.setHorizontalGroup(
            layoutm.createParallelGroup()
            .addComponent(self.mapLabel)
            .addGroup(layoutm.createSequentialGroup().addComponent(self.mapFilterLabel).addComponent(self.mapFilterTextField))
            .addComponent(self.mapPane)
            .addGroup(layoutm.createSequentialGroup().addComponent(self.clearMapBtn).addComponent(self.mapMapBtn)))
        layoutm.setVerticalGroup(
            layoutm.createSequentialGroup()
            .addComponent(self.mapLabel)
            .addGroup(layoutm.createParallelGroup(swing.GroupLayout.Alignment.BASELINE).addComponent(self.mapFilterLabel).addComponent(self.mapFilterTextField))
            .addComponent(self.mapPane)
            .addGroup(layoutm.createParallelGroup(swing.GroupLayout.Alignment.BASELINE).addComponent(self.clearMapBtn).addComponent(self.mapMapBtn)))

    def initSettingsPanel(self):
        self.settingsPanel = JPanel()
        
        # Scope checkbox
        self.scopeCheckBox = JCheckBox("Only scan items in target scope")
        
        # Exclusion List
        self.exclusionLabel = JLabel("Exclusion List (one item per line):")
        self.exclusionTextArea = JTextArea(5, 30)
        self.exclusionTextArea.setText("\n".join(JSExclusionList))
        exclusionScrollPane = JScrollPane(self.exclusionTextArea)

        # Pre-defined Regex Patterns
        self.predefinedLabel = JLabel("Pre-defined Patterns (Enable/Disable):")
        self.predefined_checkboxes = []
        predefinedPanel = JPanel()
        predefinedLayout = swing.GroupLayout(predefinedPanel)
        predefinedPanel.setLayout(predefinedLayout)
        hGroup = predefinedLayout.createParallelGroup()
        vGroup = predefinedLayout.createSequentialGroup()
        for description, pattern in PREDEFINED_REGEXES:
            checkbox = JCheckBox(description)
            self.predefined_checkboxes.append((checkbox, pattern))
            hGroup.addComponent(checkbox)
            vGroup.addComponent(checkbox)
        predefinedLayout.setHorizontalGroup(hGroup)
        predefinedLayout.setVerticalGroup(vGroup)
        
        # Custom Regex Text Area
        self.regexLabel = JLabel("Your Custom Regex Patterns (one per line):")
        self.regexTextArea = JTextArea(8, 30)
        regexScrollPane = JScrollPane(self.regexTextArea)

        # Settings Layout
        layout = swing.GroupLayout(self.settingsPanel)
        self.settingsPanel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addComponent(self.scopeCheckBox)
            .addComponent(self.exclusionLabel)
            .addComponent(exclusionScrollPane)
            .addComponent(self.predefinedLabel)
            .addComponent(predefinedPanel)
            .addComponent(self.regexLabel)
            .addComponent(regexScrollPane))
        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.scopeCheckBox)
            .addComponent(self.exclusionLabel)
            .addComponent(exclusionScrollPane)
            .addComponent(self.predefinedLabel)
            .addComponent(predefinedPanel)
            .addComponent(self.regexLabel)
            .addComponent(regexScrollPane))

    def getTabCaption(self): return "BurpJSLinkFinder"
    def getUiComponent(self): return self._parentPane
    def clearLog(self, event):
        self.all_log_entries = [
            "BurpJS LinkFinder loaded.",
            "Copyright (c) 2022 Frans Hendrik Botes",
            "Copyright (c) 2025 Kevin Dsouza"
        ]
        self.apply_filter()
    def clearFilesLog(self, event):
        self.all_filenames = []
        self.apply_filter()
    def clearMAPLog(self, event):
        self.all_mapped_urls = []
        self.apply_filter()
    def exportLog(self, event):
        fc = JFileChooser()
        if fc.showSaveDialog(self.logPanel) == JFileChooser.APPROVE_OPTION:
            with open(fc.getSelectedFile().getCanonicalPath(), 'w') as f:
                f.write(self.outputTxtArea.text)
            
    def apply_filter(self):
        # Applies filters to all three text areas
        log_filter = self.filterTextField.getText().lower()
        self.outputTxtArea.setText("\n".join(l for l in self.all_log_entries if log_filter in l.lower()))
        file_filter = self.fileFilterTextField.getText().lower()
        self.filesTxtArea.setText("\n".join(f for f in self.all_filenames if file_filter in f.lower()))
        map_filter = self.mapFilterTextField.getText().lower()
        self.mapTxtArea.setText("\n".join(m for m in self.all_mapped_urls if map_filter in m.lower()))
        for area in [self.outputTxtArea, self.filesTxtArea, self.mapTxtArea]: area.setCaretPosition(0)

    def doPassiveScan(self, ihrr):
        try:
            urlReq = ihrr.getUrl()
            
            # 1. Scope Check
            if self.scopeCheckBox.isSelected() and not self.callbacks.isInScope(urlReq): return None

            testString = str(urlReq)
            if ".js" in testString:
                # 2. Exclusion List Check
                exclusions = [e.strip() for e in self.exclusionTextArea.getText().splitlines() if e.strip()]
                if any(x in testString for x in exclusions): return None
                
                # 3. Assemble all active regex patterns
                enabled_patterns = [p for cb, p in self.predefined_checkboxes if cb.isSelected()]
                user_patterns = [p.strip() for p in self.regexTextArea.getText().splitlines() if p.strip()]
                final_regex_str = "\n".join(enabled_patterns + user_patterns)
                
                linkA = linkAnalyse(ihrr, self.callbacks, self.helpers, final_regex_str)

                self.all_log_entries.append("[+] Valid URL found: " + testString)
                issueText = linkA.analyseURL()
                if not issueText: return None

                links, full_urls, highlights = [], [], []
                
                for item in issueText:
                    link, base_url = item['link'], str(urlReq)
                    self.all_log_entries.append("\t" + link)
                    full_url = urlparse.urljoin(base_url, link) if not link.lower().startswith(('http:', 'https:')) else link
                    
                    if full_url and full_url not in self.all_mapped_urls:
                        self.all_mapped_urls.append(full_url)
                        if full_url not in full_urls: full_urls.append(full_url)

                    if link not in links: links.append(link)
                    if [item['start'], item['end']] not in highlights: highlights.append([item['start'], item['end']])

                    filNam = path.basename(link.split('?')[0].split('#')[0])
                    if linkA.isNotBlank(filNam) and linkA.checkValidFile(filNam) and filNam not in self.all_filenames:
                        self.all_filenames.append(filNam)
                
                SwingUtilities.invokeLater(Run(self.apply_filter))
                
                if links:
                    issues = ArrayList()
                    issues.add(SRI(ihrr, self.helpers, self.callbacks, links, full_urls, highlights))
                    return issues
                        
        except Exception as e:
            self.callbacks.printError("Error in doPassiveScan: " + str(e))
        return None
        
    def consolidateDuplicateIssues(self, isb, isa): return -1
    def extensionUnloaded(self): self.callbacks.printOutput("BurpJS LinkFinder v2 unloaded")

    def mapMaps(self, event):
        self.q = queue.Queue()
        for url in list(set(self.all_mapped_urls)):
            if url: self.q.put(url.strip())
        if not self.q.empty():
            self.callbacks.printOutput("Mapping {} URLs...".format(self.q.qsize()))
            for _ in range(10): threading.Thread(target=self.ProcessQueue).start()
        else: self.callbacks.printOutput("No URLs to map.")

    def ProcessQueue(self):
        while not self.q.empty():
            try:
                url = self.q.get(timeout=1)
                self.ProcessURL(url)
                self.q.task_done()
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

class linkAnalyse():
    def __init__(self, reqres, callbacks, helpers, custom_regex_str=""):
        self.callbacks, self.helpers, self.reqres = callbacks, helpers, reqres
        self.custom_regex_str = custom_regex_str
    
    # Default built-in regex for finding links
    default_regex_str = r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/.]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|/][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"|']{0,}|)))(?:"|')"""

    def parser_file(self, content):
        items = []
        all_regexes = [self.default_regex_str] + [r.strip() for r in self.custom_regex_str.splitlines() if r.strip()]
        
        for r_str in all_regexes:
            try:
                # Use re.VERBOSE for default regex, not for user's custom regex
                flags = re.VERBOSE if r_str == self.default_regex_str else 0
                regex = re.compile(r_str, flags)
                for m in re.finditer(regex, content):
                    # For default regex, the match is in group 1. For custom, it could be group 1 or group 0.
                    match_text = m.group(1) if r_str == self.default_regex_str and m.groups() else (m.group(1) if m.groups() else m.group(0))
                    items.append({"link": match_text.strip('\'"'), "start": m.start(0), "end": m.end(0)})
            except re.error as e:
                self.callbacks.printError("Regex Error for '{}': {}".format(r_str, str(e)))

        # De-duplicate results
        all_links, no_dup_items = set(), []
        for item in items:
            if item["link"] not in all_links:
                all_links.add(item["link"])
                no_dup_items.append(item)
        return no_dup_items
    
    def analyseURL(self):
        resp_bytes = self.reqres.getResponse()
        if not resp_bytes: return []
        if self.helpers.analyzeResponse(resp_bytes).getStatedMimeType().lower() == 'script':
            return self.parser_file(self.helpers.bytesToString(resp_bytes))
        return []

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