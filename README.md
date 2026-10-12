# Domain WHOIS Intelligence Tool 🕵️‍♂️

A Python-based Open-Source Intelligence (OSINT) utility built for Security Operations Center (SOC) analysts to rapidly investigate suspicious domain names and identify malicious infrastructure.

**Features:**
* Utilizes the `python-whois` library to query global domain registries directly from the desktop.
* Automatically sanitizes user input (stripping URL schemes and paths) to isolate the root domain for accurate querying.
* Highlights critical threat indicators at the top of the output, such as Creation Dates (to identify Newly Registered Domains) and Registrar information.
* Implements background threading to ensure the Tkinter GUI remains fully responsive during high-latency registry lookups.

*Built as Day 27 of a 30-Day Network Engineering & Security portfolio streak.*
