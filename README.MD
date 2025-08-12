# Certificate Fetcher for Hestia Control Panel

A Python script that automates the login and SSL certificate retrieval process from Hestia Control Panel (HestiaCP) web interfaces.

## Features

- **Automated Login Flow**: Handles complete authentication with username/password
- **Session Management**: Manages cookies and CSRF tokens automatically
- **SSL Certificate Extraction**: Retrieves certificates, private keys, and CA bundles
- **Batch Processing**: Fetches certificates for all domains or specific domain
- **File Output**: Saves certificates to organized files (CRT, KEY, CA, fullchain)
- **Rich Logging**: Enhanced logging with color output and debug mode
- **Error Handling**: Comprehensive error handling with detailed feedback

## Requirements

The script automatically installs required dependencies, but you can also install them manually:

```bash
pip install httpx rich rich-argparse
```

### Dependencies

- `httpx` - Modern HTTP client for API requests
- `rich` - Rich text and beautiful formatting in terminal
- `rich-argparse` - Rich help formatter for argparse

## Installation

1. Clone or download the script:
```bash
git clone <repository-url>
cd Hastia_Panel_CertFetcher
```

2. Make the script executable (optional):
```bash
chmod +x cert_fetcher.py
```

## Usage

### Basic Usage

```bash
python cert_fetcher.py -U https://your-hestia-panel.com -u username -p password
```

### Common Options

```bash
# Write certificates to files
python cert_fetcher.py -U https://panel.example.com -u admin -p password -w

# Specify custom output directory
python cert_fetcher.py -U https://panel.example.com -u admin -p password -w -o /path/to/certs

# Fetch certificate for specific domain only
python cert_fetcher.py -U https://panel.example.com -u admin -p password -w -d example.com

# Enable debug logging
python cert_fetcher.py -U https://panel.example.com -u admin -p password -w --debug
```

### Command Line Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| `--url` | `-U` | Yes | Base URL of the Hestia Control Panel |
| `--username` | `-u` | Yes | Username for login |
| `--password` | `-p` | Yes | Password for login |
| `--write-to-file` | `-w` | No | Write certificates to files |
| `--output-dir` | `-o` | No | Output directory (default: `./certificates`) |
| `--domain` | `-d` | No | Specific domain to fetch |
| `--debug` | | No | Enable debug logging |
| `--version` | `-v` | No | Show version and exit |
| `--help` | `-h` | No | Show help message |

## Output Files

When using the `--write-to-file` option, the script creates the following files for each domain:

```
certificates/
├── example.com.crt        # SSL Certificate
├── example.com.key        # Private Key
├── example.com.ca         # Certificate Authority Bundle
└── fullchain_example.com.pem  # Full Certificate Chain (cert + CA)
```

## Examples

### Example 1: Basic Certificate Retrieval
```bash
python cert_fetcher.py -U https://panel.mydomain.com -u admin -p mypassword -w
```

### Example 2: Debug Mode with Custom Directory
```bash
python cert_fetcher.py \
  -U https://control.example.com \
  -u username \
  -p password \
  -w \
  -o /etc/ssl/certs \
  --debug
```

### Example 3: Single Domain
```bash
python cert_fetcher.py \
  -U https://hestia.example.com \
  -u admin \
  -p secretpass \
  -w \
  -d mydomain.com
```

## Security Considerations

- **Credentials**: Never hardcode credentials. Use environment variables or secure credential storage
- **SSL Verification**: The script disables SSL verification by default for self-signed panels
- **File Permissions**: Ensure certificate files have appropriate permissions (600/644)
- **Logging**: Avoid debug mode in production to prevent credential leakage

### Using Environment Variables

```bash
export HESTIA_URL="https://panel.example.com"
export HESTIA_USER="admin"
export HESTIA_PASS="password"

python cert_fetcher.py -U "$HESTIA_URL" -u "$HESTIA_USER" -p "$HESTIA_PASS" -w
```

## Troubleshooting

### Common Issues

1. **Login Failed**
   - Verify URL, username, and password
   - Check if 2FA is enabled (not currently supported)
   - Ensure the panel is accessible

2. **No Certificates Found**
   - Verify domain exists in the panel
   - Check if SSL is configured for the domain
   - Use debug mode to see detailed logs

3. **Permission Denied**
   - Check output directory permissions
   - Ensure you have write access to the target directory

### Debug Mode

Enable debug mode to see detailed information:

```bash
python cert_fetcher.py -U https://panel.com -u user -p pass --debug
```

Debug mode shows:
- HTTP requests and responses
- Cookie and session management
- Token extraction process
- Certificate parsing details

## How It Works

1. **Login Process**:
   - GET `/login/` - Fetch login page and extract CSRF token
   - POST username with token
   - POST password with token
   - Verify successful authentication

2. **Certificate Retrieval**:
   - GET `/list/web/` - Fetch domain list
   - For each domain: GET `/edit/web/{domain}` - Fetch certificate page
   - Parse HTML to extract certificate, key, and CA values
   - Save to files if requested

3. **Session Management**:
   - Automatically handles HESTIASID cookies
   - Updates CSRF tokens for each request
   - Maintains proper referer headers

## API Reference

### cert_fetcher Class

The main class that handles the certificate fetching process.

#### Key Methods

- `run()` - Main entry point, executes the full workflow
- `full_login_flow()` - Handles authentication and certificate retrieval
- `write_certificate_to_file(domain_data)` - Saves certificates to files

#### Configuration

The class accepts an `args` object with the following attributes:
- `url` - Panel URL
- `username` - Login username  
- `password` - Login password
- `write_to_file` - Boolean for file output
- `output_dir` - Output directory path
- `domain` - Specific domain filter
- `debug` - Debug logging flag

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### Version 1.0.0
- Initial release
- Basic login and certificate retrieval
- File output support
- Debug logging
- Rich terminal output

## Support

For issues, questions, or contributions, please open an issue on the project repository.