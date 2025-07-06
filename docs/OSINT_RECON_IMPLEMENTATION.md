# OSINT & Reconnaissance Implementation

## Overview
Successfully moved OSINT Gathering from the Enumeration page to a dedicated OSINT & Reconnaissance page under the main menu, and enhanced it with metadata analysis capabilities based on the specification from `09 - Contactless Information gathering.md`.

## Changes Made

### Files Modified:
1. **`app/pages/enumeration_page.py`** - Removed OSINT Gathering from enumeration tools list
2. **`app/pages/osint_page.py`** - Enhanced existing OSINT page with metadata analysis tab
3. **`app/main_window.py`** - Added navigation alias for osint_recon

## Features Implemented

### OSINT & Reconnaissance Page Structure:
The page now contains 4 comprehensive tabs:

#### 1. **Breach Hunting Tab**
- **Have I Been Pwned**: Check email addresses against HIBP database
- **Dehashed**: Query Dehashed API for breach data
- **Breach Database**: Search local breach databases
- **All Sources**: Comprehensive breach checking across all sources

#### 2. **Employee Enumeration Tab**
- **LinkedIn**: Search for company employees on LinkedIn
- **Hunter.io**: Use Hunter.io API for email discovery
- **Clearbit**: Query Clearbit API for company information
- **Email Patterns**: Generate common email format patterns

#### 3. **Social Media Tab**
- **Twitter/X**: Search Twitter for target information
- **Facebook**: Query Facebook Graph API
- **Instagram**: Search Instagram for target data
- **GitHub**: Search GitHub for exposed credentials and sensitive data
- **All Platforms**: Comprehensive social media intelligence gathering

#### 4. **Metadata Analysis Tab** ✨ (New Implementation)
- **File Upload**: Browse and select files for analysis
- **Extract Metadata**: Basic metadata extraction using exiftool
- **Detailed Analysis**: Comprehensive metadata analysis
- **Security Check**: Focus on security-relevant metadata fields
- **Tool Integration**: Full exiftool integration with installation guidance

### Metadata Analysis Capabilities

#### Core Functionality:
- **File Support**: PDF, Office documents, images, and all file types
- **exiftool Integration**: Complete integration with exiftool command-line utility
- **Security Focus**: Highlights security-relevant metadata fields
- **Installation Guidance**: Provides installation instructions for missing tools

#### Security-Relevant Metadata Detection:
- **Author Information**: Document creator and author details
- **Software Details**: Application name and version used to create files
- **Operating System**: Client OS information
- **GPS Data**: Location information embedded in files
- **Creation Dates**: Document creation and modification timestamps
- **Comments**: Hidden comments and annotations

#### Analysis Features:
- **Color-Coded Output**: Security-relevant fields highlighted in red/orange
- **Formatted Display**: Clean, readable metadata presentation
- **Security Summary**: Automatic summary of security-relevant findings
- **Error Handling**: Graceful handling of missing tools and file errors

## Technical Implementation

### Metadata Analysis Integration:
- **exiftool Commands**: 
  - Basic: `exiftool -a -u <file>` (display all and unknown tags)
  - Detailed: `exiftool -all -s <file>` (all metadata, short format)
  - Security: `exiftool -Author -Creator -Software -GPS* <file>` (security-focused)

### Tool Requirements:
- **exiftool**: Primary metadata extraction tool
  - Windows: Download from https://exiftool.org/
  - Linux: `apt-get install exiftool`
  - macOS: `brew install exiftool`

### Error Handling:
- **Tool Availability**: Automatic detection of exiftool installation
- **File Validation**: Checks for file existence before processing
- **Timeout Management**: 30-second timeout for metadata extraction
- **User Guidance**: Clear installation instructions when tools are missing

## Usage Instructions

### Accessing OSINT & Reconnaissance:
1. Launch Hackulator
2. Click "OSINT & RECON" from the main menu
3. Select desired tab (Breach Hunting, Employee Enum, Social Media, Metadata Analysis)

### Metadata Analysis Workflow:
1. Navigate to "Metadata Analysis" tab
2. Click "Browse" to select a file or drag & drop
3. Choose analysis type:
   - **Extract Metadata**: Basic metadata extraction
   - **Detailed Analysis**: Comprehensive metadata analysis
   - **Security Check**: Focus on security-relevant fields
4. Review results with security highlights
5. Use "Clear Results" to reset the output

### Security Assessment:
The metadata analysis automatically identifies and highlights:
- **Author/Creator Information**: Potential username disclosure
- **Software Versions**: Application fingerprinting opportunities
- **GPS Coordinates**: Location privacy concerns
- **System Information**: OS and environment details
- **Hidden Comments**: Potentially sensitive annotations

## Compliance with Specification

The implementation follows the original specification from `09 - Contactless Information gathering.md`:
- ✅ Metadata inspection of publicly available documents
- ✅ Author, creation date, software name & version extraction
- ✅ Operating system information detection
- ✅ exiftool integration with -a and -u flags
- ✅ Security-focused metadata analysis

## Integration Benefits

### Organizational Improvements:
- **Logical Separation**: OSINT tools now have dedicated space separate from enumeration
- **Enhanced Functionality**: Metadata analysis adds contactless intelligence gathering
- **User Experience**: Tabbed interface provides organized access to different OSINT categories
- **Tool Integration**: Seamless integration with existing Hackulator framework

### Security Testing Value:
- **Document Intelligence**: Extract sensitive information from target documents
- **Software Fingerprinting**: Identify applications and versions in use
- **Privacy Assessment**: Detect location and personal information leakage
- **Attack Surface**: Discover potential attack vectors through metadata analysis

## Future Enhancements

Potential improvements for future versions:
- **Batch Processing**: Analyze multiple files simultaneously
- **Report Generation**: Export metadata analysis results
- **API Integration**: Live integration with HIBP, Hunter.io, and other services
- **Social Media Scraping**: Automated social media intelligence gathering
- **Credential Monitoring**: Real-time breach monitoring and alerting

## Summary

The OSINT & Reconnaissance page has been successfully enhanced with comprehensive metadata analysis capabilities. The implementation provides security professionals with powerful contactless information gathering tools while maintaining the clean, organized interface of the Hackulator framework. The metadata analysis feature specifically addresses the requirements for inspecting document metadata to extract security-relevant information about target organizations.