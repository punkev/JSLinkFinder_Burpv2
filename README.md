# BurpJS LinkFinder v2

BurpJS LinkFinder v2 is a **Burp Suite extension** that passively scans JavaScript files to extract endpoints, URLs, and filenames.  
It helps penetration testers and security researchers quickly discover hidden application paths and additional attack surface embedded in JS responses.

Inspired by [GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder) and adapted for Burp Suite as a passive scanner extension:contentReference[oaicite:0]{index=0}.

---

## ✨ Features

- **Passive Scanning**  
  Automatically analyzes JS files passing through Burp’s proxy or scanner, no manual triggering required.

- **Regex-based Link Discovery**  
  Uses a robust default regex to extract:
  - Full URLs (`http://`, `https://`, `//`)
  - Relative paths (`/`, `../`, `./`)
  - Common file types (`.php`, `.asp`, `.jsp`, `.json`, `.html`, `.js`, `.xml`, etc.)

- **Custom Regex Support**  
  Add your own regex patterns via the **Settings** tab.

- **Exclusion List**  
  Skip common libraries such as `jquery`, `google-analytics`, `modernizr`, etc. (fully customizable in the UI).

- **Organized Output**  
  Separate panes for:
  - **Log**: scanner messages and activity  
  - **Filenames**: discovered file names  
  - **Mapped URLs**: fully normalized URLs

- **Filtering in the UI**  
  Each pane supports real-time filtering with text boxes.

- **Export & Clear**  
  Export discovered data to a file or clear panes as needed.

- **Site Map Integration**  
  One-click option to add discovered URLs to Burp’s Site Map for deeper analysis.

---

## 🖥️ Screenshots

*(Add screenshots here after running in Burp — e.g., showing the custom tab, log output, and mapped URLs)*

---

## 📦 Installation

### Requirements
- [Burp Suite Community or Professional](https://portswigger.net/burp)  
- [Jython standalone 2.7.x JAR](https://www.jython.org/download) (needed to run Python extensions in Burp)  

### Steps
1. Download the latest [release](https://github.com/your-username/JSLinkFinder_Burpv2/releases) or clone this repo.
2. Open Burp → **Extender** → **Options** → set the path to your `jython-standalone-2.7.x.jar`.
3. Go to **Extender** → **Extensions** → **Add**:
   - Extension type: **Python**
   - Extension file: select `FransLinkfinder.py` (or your renamed file)
4. After loading, a new tab **BurpJSLinkFinder** will appear.

---

## ⚙️ Usage

1. Browse the target application through Burp Proxy as usual.
2. The extension will passively scan all `.js` files.
3. Open the **BurpJSLinkFinder** tab to view:
   - Logs of processed JS files
   - Extracted filenames
   - Fully mapped URLs
4. Use filters in each pane to quickly find relevant entries.
5. Optionally, export results to a file or map them directly to Burp’s Site Map.

---

## 🛠️ Settings

- **Scope checkbox**: restrict scanning only to in-scope items.  
- **Exclusion List**: specify substrings to ignore (e.g., third-party libraries).  
- **Custom Regex Patterns**: define additional regex patterns (one per line) for advanced discovery.

---

## 🚧 Limitations

- Runs in **Jython**, so syntax must remain Python 2.7–compatible.
- Regex may produce false positives or miss heavily obfuscated JS.
- Large JS files may impact performance.

---

## 📜 License

This project is licensed under the **MIT License**.  
© 2022 Frans Hendrik Botes.  

See the [LICENSE](LICENSE) file for full text.  

---

## 🙏 Credits

- [Frans Hendrik Botes](https://github.com/InitRoot) — original author  
- [GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder) — inspiration for regex and methodology  
