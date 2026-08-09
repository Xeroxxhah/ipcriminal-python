# criminalip-python

A Python client for the CriminalIP API. It provides a simple interface for querying IP, domain, and security intelligence data from CriminalIP using your API key.

## Features

- Query IP reputation and enrichment data
- Investigate domains and related metadata
- Access CriminalIP threat intelligence endpoints
- Easy-to-use Python API with environment variable support

## Installation

Install from PyPI:

```bash
pip install criminalip-python
```

Or install from source:

```bash
git clone https://github.com/your-org/criminalip-python.git
cd criminalip-python
pip install .
```

## Configuration

Set your API key as an environment variable:

```bash
export CRIMINALIP_API_KEY="your_api_key_here"
```

You can also pass the key directly when creating the client.

## Quick Start

```python
from criminalip import CriminalIP

client = CriminalIP(api_key="your_api_key_here")

# Look up an IP address
ip_info = client.ip("8.8.8.8")
print(ip_info)

# Look up a domain
site_info = client.domain("example.com")
print(site_info)
```

## Using Environment Variables

```python
import os
from criminalip import CriminalIP

client = CriminalIP(api_key=os.environ["CRIMINALIP_API_KEY"])

result = client.ip("1.1.1.1")
print(result)
```

## Example: Domain Search

```python
from criminalip import CriminalIP

client = CriminalIP(api_key="your_api_key_here")

result = client.search("example.com")
print(result)
```

## Error Handling

```python
from criminalip import CriminalIP

try:
    client = CriminalIP(api_key="your_api_key_here")
    print(client.ip("8.8.8.8"))
except Exception as e:
    print(f"Request failed: {e}")
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request with your changes.

## Support

For questions or support, refer to the CriminalIP API documentation or open an issue in this repository.
