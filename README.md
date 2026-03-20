# Offensive360 SAST for Visual Studio

Enterprise SAST (Static Application Security Testing) scanning integrated directly into Visual Studio 2022. Scan your source code for security vulnerabilities without leaving your IDE, with results displayed in the familiar Error List window.

## Screenshots

### Visual Studio with Offensive360 Extension
![Offensive360 Extension Overview](https://raw.githubusercontent.com/offensive360/VisualStudio/main/images/overview.png)

### Launching a Scan from the Build Menu
![Build Menu - Offensive 360 Scan](https://raw.githubusercontent.com/offensive360/VisualStudio/main/images/build-menu.png)

### Scan in Progress
![Scan In Progress](https://raw.githubusercontent.com/offensive360/VisualStudio/main/images/scan-progress.png)

### Scan Results in the Error List
![Scan Results](https://raw.githubusercontent.com/offensive360/VisualStudio/main/images/scan-results.png)

## Features

- **One-click security scanning** of your entire solution or project
- **Real-time results** displayed in the Visual Studio Error List window
- **Vulnerability details** including severity, description, and affected file/line
- **Suppress findings** directly from the IDE for false positives or accepted risks
- **Quick help** with contextual vulnerability information and remediation guidance
- **Clear all findings** to reset the Error List before a fresh scan

## Requirements

- **Visual Studio 2022** (version 17.0 or later)
- An active **Offensive360** account with a valid access token
- Network access to your Offensive360 server endpoint

## Installation

### From Visual Studio Marketplace

1. Open Visual Studio 2022
2. Go to **Extensions > Manage Extensions**
3. Search for **Offensive360**
4. Click **Download** and restart Visual Studio

### From VSIX File

1. Download the `.vsix` file from the [Releases](https://github.com/offensive360/VisualStudio/releases) page
2. Double-click the `.vsix` file to install
3. Restart Visual Studio

## Configuration

1. Open Visual Studio 2022
2. Navigate to **Tools > Options > Offensive 360**
3. Enter your **Endpoint** (your Offensive360 server URL)
4. Enter your **Access Token**
5. Click **OK** to save

## Usage

1. Open a solution or project in Visual Studio
2. Go to **Build > Offensive 360 : Scan**
3. Wait for the scan to complete
4. Review the results in the **Error List** window

### Additional Commands

- **Build > Offensive 360 : Clear All Errors** — Clear all scan findings from the Error List
- **Build > Offensive 360 : Suppress** — Suppress selected findings
- **Build > Offensive 360 : Get Help** — View detailed information about a selected vulnerability

## Scan Results

Results are displayed in the **Error List** window with the following information:

- **Severity** — Warning level of the vulnerability
- **Description** — Summary of the security issue
- **File** — Source file where the vulnerability was detected
- **Line** — Line number of the affected code

## Supported Languages

C#, Java, JavaScript, TypeScript, Python, PHP, Go, Ruby, Kotlin, Swift, Objective-C, Dart/Flutter, C/C++, Apex, and more. For a full list of supported languages, visit [offensive360.com](https://offensive360.com).

## License

Copyright (c) Offensive360. All rights reserved.

## Links

- Website: [https://offensive360.com](https://offensive360.com)
- Contact Us: https://offensive360.com/contact
