# VMS Client

**Official Python package to interact with the Exodus Intelligence API. Compatible with Python 3.8+.**

**Pre-Requisits:**
An Exodus Intelligence Account is required. Visit https://vpx.exodusintel.com to obtain an account.

**Getting started**
Installation via pip:

```bash
$ pip install vms_client  [TODO]
```
**Manual installation:**

Download the wheel file from <here>:

```bash
$ pip install exodus_vms.whl
```

or you can clone the repo

```bash
$ git clone url
$ cd vms
$ pip install -r requirements.txt
```

**Example Usage:** 

```python
>>> from exodus_VMS import client
>>> email = "myemail@provider.com"
>>> password = "abc123"
>>> key = "My_Exodus_Intelligence_API_Key"
>>> vms = client.Client(email, password, key)
>>> vms.get_recent_vulns()['data']['items'][0]
>>> {'access_vector': '...',
     'attack_vector': ...,
     'cpes': ...,
     'created_timestamp': '...',
     'cves': ['...'],
     'cvss': ...,
     'description': "...",
     'identifier': '...',
     'modified_timestamp': '...',
     'product': '...',
     'publish_date': '...',
     'reported': ...,
     'updated_date': '...',
     'vendor': 'GitLab',
     'xi_scores': ...,
     'zdis': ...}
>>>
```

```
Help on module vms:

NAME
    vms

CLASSES
    builtins.object
        Client
    
    class Client(builtins.object)
     |  Client(email, password, key=None) -> None
     |  
     |  Class client to communicate with the Exodus API.
     |  
     |  This module allows to connect and interact with the
     |  Exodus Intelligence API.
     |  
     |  
     |  Methods defined here:
     |  
     |  __init__(self, email, password, key=None) -> None
     |      Init the Client class.
     |      
     |      Args:
     |          email (str): Email address registered with Exodus Intelligence.
     |          password (str): User password
     |          key (str, optional): Exodus Intelligence API key. Defaults to None.
     |  
     |  decrypt_bronco_in_report(self, report, bronco_public_key)
     |      Decrypt the content of a report using a private and public key.
     |      
     |      Args:
     |          report (object): The encrypted message.
     |          bronco_public_key (str): The public key
     |      
     |      Returns:
     |          dict: A decrypted report.
     |  
     |  generate_key_pair(self)
     |      Generate a Key Pair. It does not reset the user's key.
     |      
     |      Raises:
     |          InvalidStateError: Could not set the public key.
     |          InvalidStateError: Could not confirm the public key.
     |      
     |      Returns:
     |          tuple: A key pair (sk, pk)
     |  
     |  get_access_token(self)
     |      Obtain access token.
     |      
     |      Raises:
     |          ConnectionError: When a connection to API is unavailable.
     |      
     |      Returns:
     |          str: The token.
     |  
     |  get_bronco_public_key(self)
     |      Get server public key.
     |      
     |      Returns:
     |          str: The public key.
     |  
     |  get_recent_reports(self, reset=1)
     |      Get list of recent reports.
     |      
     |      Args:
     |          reset (int): Number of days in the past to reset.
     |      
     |      Returns:
     |          dict or None: Returns a list of reports or None.
     |  
     |  get_recent_vulns(self, reset=1)
     |      Get a list of recent vulnerabilities.
     |      
     |      Args:
     |          reset (int): Number of days in the past to reset.
     |      
     |      Returns:
     |          dict: Returns a list of vulnerabilities.
     |  
     |  get_report(self, identifier)
     |      Get a report by identifier.
     |      
     |      Args:
     |          identifier (str): String representation of report id.
     |      
     |      Returns:
     |          dict: Returns report or None.
     |  
     |  get_vuln(self, identifier)
     |      Get a Vulnerability by identifier or cve.
     |      
     |      ie: x.get_vuln('CVE-2020-9456') or x.get_vuln('XI-00048890') both
     |      refer to the same vulnerability.
     |      
     |      Args:
     |          identifier (str): String representation of vulnerability id.
     |      
     |      Returns:
     |          dict: Returns a vulnerability
     |  
     |  get_vulns_by_day(self)
     |      Get vulnerabilities by day.
     |      
     |      Returns:
     |          dict or None: Returns a list of vulnerabilities.
     |  
     |  handle_reset_option(self, reset)
     |      Reset number of days.
     |      
     |      Args:
     |          reset (int): Number of days in the past to reset
     |      
     |      Returns:
     |          datetime:  A date
     |  
     |  ----------------------------------------------------------------------
     |  Data descriptors defined here:
     |  
     |  __dict__
     |      dictionary for instance variables (if defined)
     |  
     |  __weakref__
     |      list of weak references to the object (if defined)
     |  
     |  ----------------------------------------------------------------------
     |  Data and other attributes defined here:
     |  
     |  url = 'https://vpx.exodusintel.com/'

FUNCTIONS
    verify_email(email)
        Verify email's format.
        
        Args:
            email: email address.
        
        Raises:
            ValueError: If `email` is not a string.
            ValueError: If `email` format is invalid.
        
        Returns:
            bool: True

```