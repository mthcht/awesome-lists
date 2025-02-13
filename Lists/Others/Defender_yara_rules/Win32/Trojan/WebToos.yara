rule Trojan_Win32_WebToos_A_2147688310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebToos.A"
        threat_id = "2147688310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebToos"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2|%s|1|%s|%d|1|15|5|%d|" ascii //weight: 1
        $x_1_2 = {00 73 76 63 68 30 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "%s d9:link_list51:continue|" ascii //weight: 1
        $x_1_4 = "|9:task_listl%see" ascii //weight: 1
        $x_1_5 = "Presto/2.|D&8&18|.|D&90&890| Version/|D&|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_WebToos_B_2147688311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebToos.B"
        threat_id = "2147688311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebToos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 57 65 62 54 6f 6f 73}  //weight: 1, accuracy: High
        $x_1_2 = {00 49 45 63 74 72 6c 2e 6c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_3 = "New CIEThreadEx..." ascii //weight: 1
        $x_1_4 = "OnClick: %s-->%s" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Internet Explorer\\Version Vector" ascii //weight: 1
        $x_1_6 = {5c 49 45 43 74 72 6c 5c [0-8] 5c 49 45 43 74 72 6c 2e 70 64 62 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_WebToos_C_2147689647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebToos.C"
        threat_id = "2147689647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebToos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 65 62 54 6f 6f 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 49 53 50 49 44 5f 4e 45 57 57 49 4e 44 4f 57 32 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 0a}  //weight: 1, accuracy: High
        $x_1_3 = "s_svost.ini" ascii //weight: 1
        $x_1_4 = "taskh0st.exe" ascii //weight: 1
        $x_5_5 = {c6 44 24 3c 05 6a 0c 68 ?? ?? ?? ?? 8d 4c 24 20 89 6c 24 38 89 5c 24 34 88 5c 24 24 e8 ?? ?? ?? ?? 8d 44 24 18 50 c6 44 24 40 06 e8 ?? ?? ?? ?? c6 44 24 3c 05 83 7c 24 30 10 72 0d 8b 4c 24 1c 51 e8 ?? ?? ?? ?? 83 c4 04 6a 0b 68}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WebToos_D_2147689648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebToos.D"
        threat_id = "2147689648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebToos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 65 62 54 6f 6f 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 49 53 50 49 44 5f 4e 45 57 57 49 4e 44 4f 57 32 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 0a}  //weight: 1, accuracy: High
        $x_1_3 = {00 74 61 73 6b 5f 6c 69 73 74 00 00 00 6c 69 6e 6b 5f 6c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {58 57 65 62 42 72 6f 77 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = "IEctrl.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

