# APK Secret Scanner

![Author](https://img.shields.io/badge/Author-Abhishek%20Karle-blue.svg)
![Python](https://img.shields.io/badge/Python-3.6%2B-blue.svg)

A Python script to decompile APK files, scan for hardcoded secrets, and provide detailed information about their locations.

## Overview

This script automates the process of decompiling APK files and scanning for hardcoded secrets using the `jadx` tool and regular expressions. It provides a detailed output that includes the secrets' values, the file paths where they were found, the line numbers, the corresponding code snippets, and more.

## Features

- Decompiles APK files using the `jadx` tool.
- Scans for hardcoded secrets using regular expressions.
- Provides detailed information about secret locations and code snippets.

## Usage

1. Install Python 3.6 or later.
2. Clone this repository:

   ```bash
   git clone https://github.com/abhi-recon/apk-secret-scanner.git
   cd apk-secret-scanner
Run the script with an APK file as a command-line argument:

python apk_decompiler.py path/to/your.apk
To enable verbose output, use the --verbose flag:

python apk_decompiler.py path/to/your.apk --verbose
Dependencies
Python 3.6 or later
jadx tool (Ensure it's available in your system's PATH)
License
This project is licensed under the MIT License - see the LICENSE file for details.

Author
Name: Abhishek Karle

GitHub: abhi-recon

Email: abhishekkarle93@email.com

Feel free to contribute, report issues, or suggest improvements! 🚀
