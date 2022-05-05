# Exodus Intelligence API Client

## Prerequisites

An Exodus Intelligence Account is required. Visit https://vpx.exodusintel.com to obtain an account.

[Python](https://www.python.org/downloads/) 3.8 or newer is required.
&nbsp;
## Getting started

Installation via pip (binary):

```bash
$ pip install eve_client-1.0.0c1-py3-none-any.whl
```
[//]: # (Installation from binary: [TODO])
[//]: # ()
[//]: # (Download the wheel file from <here>:)
[//]: # ()
[//]: # (```bash)
[//]: # ($ pip install exodus_eve.whl)
[//]: # (```)
[//]: # ()
[//]: # (Installation from source:)
[//]: # ()
[//]: # (```bash)
[//]: # ($ git clone url)
[//]: # ($ cd eve)
[//]: # ($ pip install -r requirements.txt)
[//]: # (```)

## Usage

```python
>>> from eve_client import eve
>>> email = "myemail@provider.com"
>>> password = "abc123"
>>> key = "My_Exodus_Intelligence_API_Key"
>>> eve = eve.EVEClient(email, password, key)
>>> eve.get_recent_vulns()['data']['items'][0]
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
## eve_client Classes and Functions

### Classes
[//]: # (    builtins.object)
[//]: # (        Client)

#### class Client(builtins.object)

`Client(email, password, key=None) -> None`

An object that communicates with the Exodus API.

This class includes methods for requesting vulnerabilities and reports from the Exodus Intelligence API as well as methods and functions in support of those.

Example of connection initiation:

    >>> from eve_client import eve
    >>> exodus_api = eve.EVEClient('email', 'password', 'private_key')

Note: See `help(Client)` for more information.

##### Methods

`__init__(self, email, password, key=None) -> None`

Initializes and returns a newly allocated client object.

*Parameters*

    email (str): Email address registered with Exodus Intelligence.
    password (str): User password
    key (str, optional): Exodus Intelligence API key. Defaults to None.
&nbsp;

`decrypt_bronco_in_report(self, report, bronco_public_key)`

Decrypts the content of a report using a private and public key.

*Parameters*

    report (object): The encrypted message.
    bronco_public_key (str): The public key

*Returns*

    dict: A dictionary object representing the report.
&nbsp;

`generate_key_pair(self)`

Generates a key pair.

*Raises*

    InvalidStateError: Could not set the public key.
    InvalidStateError: Could not confirm the public key.

*Returns*

    tuple: A key pair (sk, pk)
&nbsp;

`get_access_token(self)`

Obtain access token.

*Raises*

    ConnectionError: When a connection to API is unavailable.

*Returns*

    str: The token.
&nbsp;

`get_bronco_public_key(self)`

Get server public key.

*Returns*

    str: A string representation of a public key.
&nbsp;

`get_recent_reports(self, reset=1)`

Get list of recent reports.

*Parameters*

    reset (int): Number of days in the past to reset.

*Returns*

    dict: Returns a list of reports.
&nbsp;

`get_recent_vulns(self, reset=None)`

Get all vulnerabilities within 60 days of the user's stream marker; limit of 50 vulnerabilities can be returned.

*Parameters*

    reset (int): Reset the stream maker to a number of days in the past.

*Returns*

    dict: Returns a list of vulnerabilities.
&nbsp;

`get_report(self, identifier)`

Get a report by identifier.

*Parameters*

    identifier (str): String representation of report id.

*Returns*

    dict: Returns either a report in json format
&nbsp;

`get_vuln(self, identifier)`

Retrieve a ulnerability by Exodus Intelligence identifier or by CVE.

*Parameters*

    identifier (str): String representation of vulnerability id.

*Returns*

    dict: Returns either a report in json format
&nbsp;

`get_vulns_by_day(self)`

Get vulnerabilities by day.

*Returns*

    dict: Returns vulnerabilities list.
&nbsp;

`handle_reset_option(self, reset)`

Reset number of days.

*Parameters*

    reset (int): Number of days in the past to reset

*Returns*

    datetime:  A date

##### Data descriptors

`__dict__`

Dictionary for instance variables (if defined).

`__weakref__`

List of weak references to the object (if defined).

##### Data and other attributes

`url = 'https://vpx.exodusintel.com/'`

### Functions

`verify_email(email)`

Verify email's format.

*Parameters*

    email: email address.

*Raises*

    ValueError: If `email` is not a string.
    ValueError: If `email` format is invalid.

*Returns*

    bool: True
