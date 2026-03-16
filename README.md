# O360 SAST for Visual Studio

Enterprise Static Application Security Testing (SAST) integrated directly into Visual Studio 2022. Scan your solution, project, or active file for security vulnerabilities without leaving your IDE. Results appear in a dedicated findings panel with direct code navigation to every vulnerability.

![Security Findings Panel](https://raw.githubusercontent.com/offensive360/VisualStudio/master/images/screenshot-findings-panel.png)

## Features

### Scan from the Build Menu
- **Scan Solution** — Scan your entire Visual Studio solution
- **Scan Active Project** — Scan the currently active project
- **Scan Active File** — Scan the file currently open in the editor

All scan options are accessible from **Build → O360 SAST** and from the **O360 Security Findings** panel toolbar.

### O360 Security Findings Panel
- **Severity Badges** — Color-coded summary showing Critical, High, Medium, Low, and Info counts
- **Findings Table** — Sortable list with severity badge, vulnerability title, file path, and line number
- **Detail Panel** — Select any finding to see full description, affected file, impact analysis, recommendation, and vulnerable code snippet
- **Code Navigation** — Double-click any finding to open the source file and jump to the exact vulnerable line
- **Real-time Progress** — Status bar shows scan progress and queue position

![Scan in Progress](https://raw.githubusercontent.com/offensive360/VisualStudio/master/images/screenshot-scan-started.png)

### Multiple Scan Types
- **Code Vulnerabilities** — 20+ language engines (C#, Java, JavaScript/TypeScript, Python, PHP, Go, Ruby, Kotlin, Swift, Dart, and more)
- **Dependency Scanning (SCA)** — Known CVEs in NuGet, npm, Maven, and other package managers
- **License Compliance** — Open source license risk detection
- **Malware Detection** — YARA-based malware scanning

### Enterprise-Ready
- On-premises or cloud O360 SAST server
- API token authentication
- Per-user settings via **Tools → Options → O360 SAST**

![Scan Results — 8 Findings](https://raw.githubusercontent.com/offensive360/VisualStudio/master/images/screenshot-findings.png)

## Getting Started

### Prerequisites

- **Visual Studio 2022** (Community, Professional, or Enterprise)
- An **O360 SAST server** instance (on-premises or cloud)
- An **API access token** (generated from the O360 dashboard)

### Installation

1. Download **OffensiveVS360.vsix** from the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=Offensive360.OffensiveVS360)
2. Double-click the `.vsix` file to install
3. Restart Visual Studio when prompted

### Configuration

1. Go to **Tools → Options → O360 SAST → Settings**
2. Set **Endpoint** — your O360 server URL (e.g., `https://your-server.com:1800`)
3. Set **Access Token** — generated from O360 dashboard → Settings → Access Tokens
4. Optionally enable **Dependency Scanning**, **License Scanning**, or **Malware Scanning**

![Settings — Tools → Options → O360 SAST](https://raw.githubusercontent.com/offensive360/VisualStudio/master/images/vs_o360_settings.png)

### First Scan

1. Open a solution in Visual Studio
2. Go to **Build → Scan Solution with O360 SAST**
3. Monitor progress in the VS status bar
4. When complete, the **O360 Security Findings** panel opens automatically
5. Click any finding to navigate to the vulnerable line
6. Review the detail panel for fix recommendations

![Code Analysis in Action](https://raw.githubusercontent.com/offensive360/VisualStudio/master/images/screenshot-code-squiggles.png)

### Opening the Findings Panel

If the panel isn't visible, go to **View → Other Windows → O360 Security Findings**.

## Settings

| Setting | Description |
|---------|-------------|
| Endpoint | O360 SAST server URL (required) |
| Access Token | API access token (required) |
| Scan Dependencies | Include SCA scanning for known CVEs |
| Scan Licenses | Include open source license compliance |
| Scan Malware | Include YARA malware scanning |

## Supported Languages

C#, Java, JavaScript, TypeScript, Python, PHP, Go, Ruby, Kotlin, Swift, Objective-C, Dart/Flutter, C/C++, Apex, and more — powered by O360's proprietary deep analysis engines and AI-assisted scanning.

## Support

- Issues: [GitHub Issues](https://github.com/offensive360/VisualStudio/issues)
- Documentation: [O360 SAST Docs](https://www.offensive360.com)
