rule Trojan_Win32_Proscks_A_2147616627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Proscks.A!dll"
        threat_id = "2147616627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Proscks"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "IPHACTION.dll" ascii //weight: 1
        $x_1_2 = "doMyAction" ascii //weight: 1
        $x_1_3 = "http://www.dofulfill" ascii //weight: 1
        $x_1_4 = {73 76 63 68 6f 73 74 2e 65 78 65 20 6c 6f 61 64 69 70 68 6f 73 74 [0-4] 25 73 5c 66 69 70 6c 6f 63 6b 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_5 = {3c 2f 77 65 62 75 72 6c 3e [0-4] 57 65 62 53 74 61 72 74 41 63 74 69 6f 6e [0-2] 3c 67 65 74 55 73 65 64 4c 6f 61 6e 44 61 74 61 3e [0-4] 3c 2f 67 65 74 55 73 65 64 4c 6f 61 6e 44 61 74 61 3e [0-4] 3c 63 6d 64 5f 77 65 62 43 6f 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Proscks_B_2147618049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Proscks.B!dll"
        threat_id = "2147618049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Proscks"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%WinDir%\\System32\\Dllcache\\svchost.exe" ascii //weight: 1
        $x_1_2 = {70 72 6f 78 79 2e 64 6c 6c 00 72 61 6e 64}  //weight: 1, accuracy: High
        $x_1_3 = "net stop \"sharedaccess\"" ascii //weight: 1
        $x_1_4 = "mac=%02X:%02X:%02X:%02X:%02X:%02X" ascii //weight: 1
        $x_1_5 = "proxy pwd=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Proscks_C_2147618052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Proscks.C!dll"
        threat_id = "2147618052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Proscks"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetReadFile" ascii //weight: 1
        $x_1_2 = "%WinDir%\\System32\\Drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = {43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 00 00 25 00 25 00 74 00 65 00 6d 00 70 00 25 00 25 00 5c 00 25 00 30 00 38 00 64 00 25 00 30 00 38 00 64 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s&ad_id=%s&ad_hour=%s&ad_viewnum=%s&ad_clicknum=%s&ver=%s" ascii //weight: 1
        $x_1_5 = {45 78 70 6f 72 74 00 58 6f 72 44 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

