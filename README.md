# yara-suricata
A Yara Lua output script for Suricata (https://suricata-ids.org/)

# Usage
In order to use this script, you will need:
1. A working Yara executable
2. Yara rules
3. Suricata file-store version 2 module, which means you'll need (at the time of this writing) Suricata 4.1.0 Beta.
4. Suricata 4.1.0+ compiled with Lua or LuaJIT support and NSS support (for hashing)

The script will need to be placed in the Suricata output scripts directory, and specified by name in output scripts section in the Suricata config file(suricata.yaml), please see https://suricata.readthedocs.io/en/latest/output/lua-output.html#yaml for the correct syntax.

Once installed and configured, you'll need to configure the rules to store the desired files to be scanned by Yara. 
There are 4 configuration options within the script that you may need to customize to suit your environment. 
They are as follows:

    suricata_filestore: The path to your Suricata file store, defaults to <Suricata log path>/filestore
    
    yara_path: The path to your Yara executable, defaults to '/usr/bin/yara'
    
    yara_rules_path: The path to your compiled Yara rules file for executable file types. Defaults to '/usr/share/yara/rules.yar'
    
    yara_non_pe_rules_path: The path to your compiled Yara rules file for non-executable file types
    
    yara_log_name: The name of the Yara log. The name defaults to 'yara.json', under the <Suricata log path>

Output looks like so:

`{"filename": "/f.tmp", "rules": ["BlackEnergy_Driver_USBMDM"],"size": 60928,"sha256": "244dd8018177ea5a92c70a7be94334fa457c1aab8a1c1ea51580d7da500c3ad5"}`
    
If there are no rule hits, the script will delete the file.
