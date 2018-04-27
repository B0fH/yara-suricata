# yara-suricata
A Yara Lua output script for Suricata

This script requires:
1. A working Yara executable
2. Yara rules
3. Suricata file-store version 2 module, which means you'll need (at the time of this writing) Suricata 4.1.0 Beta.
4. Suricata 4.1.0+ compiled with Lua or LuaJIT support

Once installed and configured, you'll need to configure the rules to store the desired files to be scanned by Yara. There are 4 configuration options within the script that you may need to customize to fit your configuration, they are as follows:

    suricata_filestore: The path to your Suricata file store, defaults to <Suricata log path>/filestore
    
    yara_path: The path to your Yara executable, defaults to '/usr/bin/yara'
    
    yara_rules_path: The path to your Yara rules file, preferably compiled. Defaults to '/usr/share/yara/rules.yar'
    
    yara_log_name: The name of the Yara log. The name defaults to 'yara.json', under the <Suricata log path>
