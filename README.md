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

**Available Class Methods:**

```
vms.decrypt_bronco_in_report()
vms.get_vulns_by_day()
vms.handle_reset_option()
vms.generate_key_pair()
vms.get_bronco_public_key()
vms.get_recent_reports()
vms.get_recent_vulns()
vms.get_report()
vms.get_vuln()
```
