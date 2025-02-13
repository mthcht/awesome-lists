rule Trojan_Win32_Gbplug_A_2147597982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gbplug.A"
        threat_id = "2147597982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gbplug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winlogon.exe" wide //weight: 1
        $x_1_2 = "Taskmgr.exe" wide //weight: 1
        $x_1_3 = "gbiehscd.dll" wide //weight: 1
        $x_1_4 = "GbPluginScd.inf" wide //weight: 1
        $x_1_5 = "scpLIB.dll" wide //weight: 1
        $x_1_6 = "scpMIB.dll" wide //weight: 1
        $x_1_7 = "scpsssh2.dll" wide //weight: 1
        $x_1_8 = "sshib.dll" wide //weight: 1
        $x_1_9 = "Downloaded Program Files\\CONFLICT.1\\g*.dll" wide //weight: 1
        $x_1_10 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

