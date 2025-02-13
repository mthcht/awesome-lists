rule MonitoringTool_Win32_IMonitor_202040_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:Win32/IMonitor"
        threat_id = "202040"
        type = "MonitoringTool"
        platform = "Win32: Windows 32-bit platform"
        family = "IMonitor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "OnHookWebMailComplete" ascii //weight: 1
        $x_1_2 = "WINDOWS\\SYSTEM32\\drivers\\imonagent\\" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\THC\\OutDevice" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\THC\\LogSetting" ascii //weight: 1
        $x_1_5 = "ipseccmd -w REG -p \"LockNet\" -r \"Pass 4820\" -f 0+*:4820:TCP -n PASS" ascii //weight: 1
        $x_1_6 = {c6 84 24 f0 02 00 00 19 e8 ?? ?? ?? 00 50 8d 4c 24 14 c6 84 24 e8 02 00 00 1a e8 ?? ?? ?? 00 8d 8c 24 a8 00 00 00 c6 84 24 e4 02 00 00 19 e8 ?? ?? ?? 00 8d 8c 24 88 00 00 00 c6 84 24 e4 02 00 00 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

