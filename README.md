# noteclass

Framework for classifying ransom note text files and using the results to detect ransomware at runtime.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Haven't tested this on another box yet, so YMMV..

```
sysmon
Python 3
spaCy
pandas
python WMI - https://pypi.org/project/WMI
pywin32api - https://pypi.org/project/pypiwin32
```

### Installing

Download all prerequisites, then install sysmon with the provided sysmon_config.xml:

```
sysmon.exe -i sysmon_config.xml
```

After that, you'll need to add the following registry key to enable querying the sysmon event log through WMI:

```
HKLM\SYSTEM\CurrentControlSet\services\eventlog\Microsoft-Windows-Sysmon/Operational
```

Proceed to install all other prerequisites then you should be good to go.

### Running

At least this is pretty simple:

```
python.exe framework.py
```

## Author

* **Mark Mager** - *Initial work* - [magerbomb](https://twitter.com/magerbomb)

## License

This project is licensed under the AGPLv3 License - see the [LICENSE-AGPLv3.txt](LICENSE-AGPLv3.txt) file for details
